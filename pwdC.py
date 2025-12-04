import threading
import bcrypt
from passlib.hash import sha256_crypt, sha512_crypt, md5_crypt
import sys
import subprocess
import json

from multiprocessing import  Value


CHARSET_LIST = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@#%^&*()_+-=.,:;?"

def int_to_password(n: int):
    if n < 0:
        raise ValueError("n must be >= 0")
    n += 1 # Using the bijective system where numbering for characters start at 1 and 0 represents an empty string
    password = []
    charset_len = len(CHARSET_LIST)


    while n > 0:
        n -= 1 # Minus 1 so you can ensure you get the correct character from the char set
        character_num = n % charset_len # Get the value of the character

        #   Add the character to the password list
        password.append(CHARSET_LIST[character_num])

        """
        Each next character beyond 79 is based on how many times 79 can be divided into the password iteration.
        n = 0; n % 79 = 0; 0 = A
        n = 78; n % 79 = 78; 78 = ?
        n = 79; n % 79 = 0; 0 = A; n //= 79 = 1; n -= 1 -> 0; n % 79 = 0; 0 = A; password = AA
        """
        n //= charset_len

    #
    return "".join(reversed(password))

def hash_md5(password: str, salt: str) -> str:
    """
    Creates a deterministic MD5-crypt hash using a provided salt.

    Parameters:
      - password: plaintext password (str)
      - salt: 8-char salt string from the shadow file (str)

    Returns:
      Full MD5 crypt hash string (e.g. '$1$salt$hashpart')
    """
    return md5_crypt.using(salt=salt).hash(password)

# ------------------------
# BCRYPT
# ------------------------
def bcrypt_hash_hex(password: str, full_salt: str) -> str:
    salt_encoded = full_salt.encode('utf-8')
    password_b = password.encode('utf-8')
    hashed = bcrypt.hashpw(password_b, salt_encoded)         # hashed is bytes (bcrypt format)

    return hashed # return hex string of the hashed bytes


def bcrypt_verify(password: str, hashed_str: str) -> bool:
    hashed_bytes = hashed_str.encode("utf-8")  # just encode, not fromhex

    return bcrypt.checkpw(password.encode(), hashed_bytes)


# ------------------------
# SHA256 (hashlib)
# ------------------------
def sha256_hash(password: str, salt: str) -> str:
    # pass explicit salt for deterministic output
    # Set default rounds to 5000 to match what is used for mkpasswd
    hashed_password = sha256_crypt.using(rounds=5000,salt=salt).hash(password)

    # Remove the "rounds=" segment manually
    cleaned_hash = hashed_password.replace(f"rounds={sha256_crypt.default_rounds}$", "")
    return cleaned_hash


# ------------------------
# SHA512 (hashlib)
# ------------------------
def sha512_hash(password: str, salt: str) -> str:
    # Use deterministic salt and set rounds to 5000 to match mkpasswd default
    hashed_password = sha512_crypt.using(rounds=5000, salt=salt).hash(password)

    # Remove the "rounds=" segment manually
    cleaned_hash = hashed_password.replace(f"rounds={sha512_crypt.default_rounds}$", "")

    return cleaned_hash

# ------------------------
# YESCRYPT
# ------------------------
def yescrypt_hash(password: str, salt: str):

    # Use predetermined salt
    result = subprocess.run(
        ['mkpasswd', '-m', 'yescrypt', '-S', salt, '--', password],
        capture_output=True,
        text=True
    )

    # Check for errors
    if result.returncode != 0:
        print(f"Error: {result.stderr}")
        return None

    return result.stdout.strip()



'''
New function to extract hash information for the Project
'''
def extract_hash_data(user_input_hash):
    # Split the data by $ and separate the algorithm code and salt
    full_hash_split = user_input_hash.split("$")
    # print(f"Full hash split: {full_hash_split}")

    # Algorithm code
    algorithm = full_hash_split[1]
    # This will be the salt, but in the case for ysecrypt this will be the cost
    salt = full_hash_split[2]
    # This will be the password hash, but in the case for yescrypt this will be the salt
    password_hash = full_hash_split[3]


    if algorithm == "1": # MD5
        return [algorithm, salt, user_input_hash]

    elif algorithm == "5": # SHA-256
        return [algorithm, salt, user_input_hash]

    elif algorithm == "6": # SHA-512
        return [algorithm, salt, user_input_hash]

    elif algorithm == "y": # Yescrypt
        # Need to adjust the variables for the cost and salt
        cost = full_hash_split[2]
        salt = full_hash_split[3]
        hash_data = [algorithm, cost, salt]

        # Build the salt that will be used in the hash function
        hash_function_salt = create_salt(hash_data)

        return [algorithm, hash_function_salt, user_input_hash]

    elif algorithm in ("2a", "2b", "2y"):
        hash_data = [algorithm, salt, password_hash]
        # Build the salt that is used in the hash function
        hash_function_salt = create_salt(hash_data)

        return [algorithm, hash_function_salt, user_input_hash]

    else:
        print(f"The hashing algorithm code {algorithm} is unknown.")
        sys.exit(2)



def create_salt(hash_data: list):
        algorithm_code = hash_data[0]

        if algorithm_code == "y":
            # hash_data = [algorithm, cost, salt]
            cost = hash_data[1]
            salt_fragment = hash_data[2]

            return f"${algorithm_code}${cost}${salt_fragment}"
        elif algorithm_code in ("2a", "2b", "2y"):
            # hash_data = [algorithm, rounds, salt_and_password]
            rounds = hash_data[1]
            # The first 22 characters of the salt_and_password is the salt
            salt_fragment = hash_data[2][:22]

            cost_str = f"{int(rounds):02d}"
            return f"{algorithm_code}${cost_str}${salt_fragment}"
        else:
            print(f"Failed to create salt."
                  f"\nThe hashing algorithm code {algorithm_code} is unknown.")
            sys.exit(2)


"""
For MD5 Cracking
"""
def crack_md5(password_hash_to_crack: str, salt: str, counter, found, process_id, batch_size: int,
              true_counter, checkpoint_counter, checkpoint_value, last_password, client_socket):
    # Do multiple found checks to see if another thread has found the value
    while not found.value:
        with counter.get_lock():
            if found.value:
                break

            # My starting password to check
            start_index = counter.value

            # The last password to check
            max_password = counter.value + batch_size

            # If my counter is larger than last password, means the last amount of work is already assigned
            if counter.value > last_password:
                return

            # If the counter + batch size is the last password or larger, then just assigned max_passowrd
            # to the last password. This is the remaining set of passwords to check.
            elif max_password >= last_password:
                # Set the max password to the very last password
                max_password = last_password
                counter.value = last_password + 1

            # If you add batch size to counter and it doesn't reach or go over max, then just add batch size to counter
            # so other threads can continue work.
            else:
                counter.value += batch_size


        for password_to_check in range(start_index, max_password):
            # time.sleep(0.01)
            if found.value:  # Check if another process found it
                break

            counter_to_password = int_to_password(password_to_check)
            hash_guess = hash_md5(counter_to_password, salt)
            # print(f"Process id {process_id} checking password {password_to_check}: {hash_guess}")

            if hash_guess == password_hash_to_crack:
                # If the password is found, then you send a message to the server
                send_found_password(password_to_check, counter_to_password, client_socket)

                print(f"Process ID {process_id} found the password")
                print('Password is cracked. Hash is:', hash_guess)
                print("The password is:", counter_to_password)
                print("Password was found at value:", password_to_check)

                # Set the found value to true so all other threads will exit
                with found.get_lock():
                    found.value = True

                # Exit immediately
                return  # Exit immediately


            else:
                with checkpoint_counter.get_lock():
                    # After every password attempt, add 1 to checkpoint counter
                    checkpoint_counter.value += 1

                    # When the password reaches the checkpoint limit, update true_counter and send a message to the server
                    if checkpoint_counter.value == checkpoint_value:
                        true_counter.value += checkpoint_counter.value
                        print(f"Process ID {process_id} is sending the checkpoint {true_counter.value}")
                        send_checkpoint(true_counter, client_socket, found)

                        # Reset checkpoint counter
                        checkpoint_counter.value = 0
"""
Bcrypt
"""


def crack_bcrypt(full_hash: str, full_salt: str, counter, found, process_id, batch_size: int,
                 true_counter, checkpoint_counter, checkpoint_value, last_password, client_socket):
    while not found.value:
        with counter.get_lock():
            if found.value:
                break

            start_index = counter.value

            max_password = counter.value + batch_size

            # No more work
            if counter.value > last_password:
                # Exit thread
                return
            # Last amount of work left
            elif max_password >= last_password:
                max_password = last_password
                counter.value = last_password + 1
            # Pull work from counter. Still more work for other threads
            else:
               counter.value += batch_size

        for password_to_check in range(start_index, max_password):
            if found.value:
                break

            counter_to_password = int_to_password(password_to_check)
            hash_guess = bcrypt_hash_hex(counter_to_password, full_salt)
            # print(f"Process {process_id} checking password {password_to_check}: {hash_guess}")

            if bcrypt_verify(counter_to_password, full_hash):
                send_found_password(password_to_check, counter_to_password, client_socket)

                print(f"Process ID {process_id} found the password")
                print('Password is cracked. Hash is:', hash_guess)
                print("The password is:", counter_to_password)
                print("Password was found at value:", password_to_check)
                with found.get_lock():
                    found.value = True

                return

            # If password is not found, increase checkpoint counter
            else:
                with checkpoint_counter.get_lock():
                    checkpoint_counter.value += 1

                    if checkpoint_counter.value == checkpoint_value:
                        true_counter.value += checkpoint_counter.value
                        print(f"Process ID {process_id} is sending the checkpoint {true_counter.value}")
                        send_checkpoint(true_counter, client_socket, found)

                        checkpoint_counter.value = 0

"""
For SHA-256
"""


def crack_sha256(full_hash: str, salt: str, counter, found, process_id, batch_size: int,
                 true_counter, checkpoint_counter, checkpoint_value, last_password, client_socket):
    while not found.value:
        with counter.get_lock():
            if found.value:
                break

            start_index = counter.value

            max_password = counter.value + batch_size

            # No more work
            if counter.value > last_password:
                # Exit thread
                return
            # Last amount of work left
            elif max_password >= last_password:
                max_password = last_password
                counter.value = last_password + 1
            # Pull work from counter. Still more work for other threads
            else:
                counter.value += batch_size


        for password_to_check in range(start_index, max_password):
            if found.value:
                break

            counter_to_password = int_to_password(password_to_check)
            hash_guess = sha256_hash(counter_to_password, salt)
            # print(f"Process {process_id} checking password {password_to_check}: {hash_guess}")

            if hash_guess == full_hash:
                send_found_password(password_to_check, counter_to_password, client_socket)

                print(f"Process ID {process_id} found the password")
                print('Password is cracked. Hash is:', hash_guess)
                print("The password is:", counter_to_password)
                print("Password was found at value:", password_to_check)
                with found.get_lock():
                    found.value = True

                return
            # If password is not found, increase checkpoint counter
            else:
                with checkpoint_counter.get_lock():
                    checkpoint_counter.value += 1

                    if checkpoint_counter.value == checkpoint_value:
                        true_counter.value += checkpoint_counter.value
                        print(f"Process ID {process_id} is sending the checkpoint {true_counter.value}")
                        send_checkpoint(true_counter, client_socket, found)

                        checkpoint_counter.value = 0


"""
For SHA-512
"""


def crack_sha512(full_hash: str, salt: str, counter, found, process_id, batch_size: int,
                 true_counter, checkpoint_counter, checkpoint_value, last_password, client_socket):
    while not found.value:
        with counter.get_lock():
            if found.value:
                break

            start_index = counter.value

            max_password = counter.value + batch_size

            # No more work
            if counter.value > last_password:
                # Exit thread
                return
            # Last amount of work left
            elif max_password >= last_password:
                max_password = last_password
                counter.value = last_password + 1
            # Pull work from counter. Still more work for other threads
            else:
                counter.value += batch_size

        for password_to_check in range(start_index, max_password):
            if found.value:
                break

            counter_to_password = int_to_password(password_to_check)
            hash_guess = sha512_hash(counter_to_password, salt)
            # print(f"Process {process_id} checking password {password_to_check}: {hash_guess}")

            if hash_guess == full_hash:
                send_found_password(password_to_check, counter_to_password, client_socket)

                print(f"Process ID {process_id} found the password")
                print('Password is cracked. Hash is:', hash_guess)
                print("The password is:", counter_to_password)
                print("Password was found at value:", password_to_check)
                with found.get_lock():
                    found.value = True

                return
            # If password is not found, increase checkpoint counter
            else:
                with checkpoint_counter.get_lock():
                    checkpoint_counter.value += 1

                    if checkpoint_counter.value == checkpoint_value:
                        true_counter.value += checkpoint_counter.value
                        print(f"Process ID {process_id} is sending the checkpoint {true_counter.value}")
                        send_checkpoint(true_counter, client_socket, found)

                        checkpoint_counter.value = 0


"""
For yescrypt
"""


def crack_yescrypt(full_hash: str, full_salt: str, counter, found, process_id, batch_size: int,
                     true_counter, checkpoint_counter, checkpoint_value, last_password, client_socket):

    while not found.value:
        with counter.get_lock():
            if found.value:
                break

            start_index = counter.value

            max_password = counter.value + batch_size

            # No more work
            if counter.value > last_password:
                # Exit thread
                return
            # Last amount of work left
            elif max_password >= last_password:
                max_password = last_password
                counter.value = last_password + 1
            # Pull work from counter. Still more work for other threads
            else:
                counter.value += batch_size

        for password_to_check in range(start_index, max_password):
            if found.value:
                break

            counter_to_password = int_to_password(password_to_check)
            hash_guess = yescrypt_hash(counter_to_password, full_salt)
            # print(f"Process {process_id} checking password {password_to_check}: {hash_guess}")

            if hash_guess == full_hash:
                send_found_password(password_to_check, counter_to_password, client_socket)

                print(f"Process ID {process_id} found the password")
                print('Password is cracked. Hash is:', hash_guess)
                print("The password is:", counter_to_password)
                print("Password was found at value:", password_to_check)
                with found.get_lock():
                    found.value = True

                return

            # If password is not found, increase checkpoint counter
            else:
                with checkpoint_counter.get_lock():
                    checkpoint_counter.value += 1

                    if checkpoint_counter.value == checkpoint_value:
                        true_counter.value += checkpoint_counter.value
                        print(f"Process ID {process_id} is sending the checkpoint {true_counter.value}")
                        send_checkpoint(true_counter, client_socket, found)

                        checkpoint_counter.value = 0


def pw_crack_worker(hash_data, process_id, counter, found, batch_size: int,
                    true_counter, checkpoint_counter, checkpoint_value, last_password
                    , client_socket):
    # hash_data = extract_hash_data()
    # print(hash_data)

    algorithm_code = hash_data[0]
    full_salt = hash_data[1]
    full_hash = hash_data[2]

    # print(f"Process ID {process_id} Started")

    if algorithm_code == "1":
        # print("This hash is using MD5")
        crack_md5(full_hash, full_salt, counter, found, process_id, batch_size,
                  true_counter, checkpoint_counter, checkpoint_value, last_password,
                  client_socket)

    elif algorithm_code == "5":
        # print("This hash is using SHA-256")
        crack_sha256(full_hash, full_salt, counter, found, process_id, batch_size,
                    true_counter, checkpoint_counter, checkpoint_value, last_password,
                    client_socket)


    elif algorithm_code == "6":
        # print("This hash is using SHA-512")
        crack_sha512(full_hash, full_salt, counter, found, process_id, batch_size,
                    true_counter, checkpoint_counter, checkpoint_value, last_password,
                    client_socket)



    elif algorithm_code == "y":
        # print("This hash is using Yescrypt")
        crack_yescrypt(full_hash, full_salt, counter, found, process_id, batch_size,
                    true_counter, checkpoint_counter, checkpoint_value, last_password,
                    client_socket)



    elif algorithm_code in ("2a", "2b", "2y"):
        # print("This hash is using bcrypt")
        crack_bcrypt(full_hash, full_salt, counter, found, process_id, batch_size,
                     true_counter, checkpoint_counter, checkpoint_value, last_password,
                     client_socket)

    else:
        print(f"The hashing algorithm code {algorithm_code} is unknown.")
        sys.exit(2)

    # print(f"Process ID {process_id} closing.")


def send_found_password(password_value, password_string, client_socket):
    msg = [0, password_value, password_string]
    json_str_bytes = json.dumps(msg).encode("utf-8")

    try:
        client_socket.send(json_str_bytes)
    except Exception as e:
        print(f"Socket sending error: {e}")


def send_checkpoint(true_counter, client_socket, found):
    msg = [2, true_counter.value]
    json_str_bytes = json.dumps(msg).encode("utf-8")

    try:
        client_socket.send(json_str_bytes)
    except Exception as e:
        print(f"Socket sending error: {e}")
        with found.get_lock():
            found.value = True






def crack_password(starting_password: int, last_password: int, checkpoint_value, full_hash_to_crack, client_socket,
                   num_threads: int):
    counter = Value('l', starting_password)
    found = Value('b', False)

    '''
    Because of how I coded my password cracker, the threads pull the passwords from the counter and update it
    before the passwords are actually checked.
    So in order to have an accurate checkpoint counter I need a separate counter for the password counter that
    holds the password value before the threads pull the work from it. Then I update this value using
    checkpoint_counter to accurate keep track of the true number of passwords checked.
    This is not the most elegant solution, but it's the most simple.
    '''
    true_counter = Value('l', starting_password)
    checkpoint_counter = Value('l', 0)

    hash_data = extract_hash_data(full_hash_to_crack)
    # print(f"The full hash that wants to be cracked: {full_hash_to_crack}")
    print(f"Hash data after separated: {hash_data}")

    # algorithm_code = hash_data[0]
    # full_salt = hash_data[1]
    # full_hash = hash_data[2]
    # print(f"Algorithm code: {algorithm_code}")
    # print(f"Full salt: {full_salt}")
    # print(f"Full hash: {full_hash}")

    # Number of passwords that each thread should be checking
    batch_size = 100

    threads = []

    for i in range(num_threads):
        t = threading.Thread(
            target=pw_crack_worker,
            args=(
                hash_data,
                i,
                counter,
                found,
                batch_size,
                true_counter,
                checkpoint_counter,
                checkpoint_value,
                last_password,
                client_socket,
            ),
            daemon = True,
        )
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    # pw_crack_worker(hash_data, 0, counter, found, batch_size,
    #                 true_counter, checkpoint_counter, checkpoint_value, last_password
    #                 , client_socket)
    #
