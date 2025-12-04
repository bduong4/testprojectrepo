import argparse
import socket
import json
from pwdC import crack_password


def client_args():
    # User argparse library to get the parameters using "--" format

    parser = argparse.ArgumentParser()

    '''
    Arguments needed:
    server
    port
    threads
    
    
    All are integer except for server.
    '''

    parser.add_argument("--server", type=str, required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--threads", type=int, required=True)

    args = parser.parse_args()

    print("Client started:")
    print(f"Server: {args.server}")
    print(f"Port: {args.port}")
    print(f"Threads: {args.threads}")

    return args


def test():
    a = "$1$cK6Uj0cv$3dIUOkv0.gONwqESvuLr31:"
    print(f"a: {a}")
    a_s = a.split(":")
    print(f"as: {a_s}")


def msg_for_work(client_socket):
    msg = [1]
    json_string_bytes = json.dumps(msg).encode("utf-8")
    try:
        client_socket.send(json_string_bytes)
    except Exception as e:
        print(f"Socket sending error: ({e})")
        return


if __name__ == '__main__':
    print("This is client node")

    # test()

    args = client_args()

    # 1. Create socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # 2. Connect to server
    ip = args.server

    port = args.port

    print(f"IP:{ip}")

    client_socket.connect((ip, port))

    num_threads = args.threads

    while True:

        # 3. Send and Receive from server
        try:
            data = client_socket.recv(1024) # 1024 bytes
            # print(f"Received operations from the server: {data}")
        except Exception as e:
            print(f"Error with socket: {e}")
            print("Issue with Server connection. Closing client.")
            break

        if data == b"":
            print(f"Server has closed the connection. No more work to do.")
            break

        recv_msg = json.loads(data)
        # print(f"Received operations after being parsed: {recv_msg}")
        # for i in recv_msg:
        #     print(i)


        operation = recv_msg[0]

        if operation == 0:

            print(f"\n{'==' * 50}")
            print("Server is closing this client.")
            break
        else:
            s_pwd = recv_msg[1]
            e_pwd = recv_msg[2]
            checkpoint = recv_msg[3]
            full_hash = recv_msg[4]

            print(f"\n{'=' * 50}")
            print(f"Work sent by server to be done. \nFirst password: {s_pwd}\nLast password: {e_pwd}")
            print(f"{'=' * 50}\n")

            crack_password(s_pwd, e_pwd, checkpoint, full_hash, client_socket, num_threads)

            msg_for_work(client_socket)







    # client_socket.send(b"This is a message from the client that is first")
    # print("Data was sent to the server.")

    # 4. Exist
    print("~~~Closing client now~~~")
    client_socket.close()



