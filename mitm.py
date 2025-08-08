# mitm.py
import socket, time
import random


class AttackException(Exception):
    pass


# Addresses and ports for the MITM
LISTEN_IP = "127.0.0.1"
LISTEN_PORT = 65431
FORWARD_IP = "127.0.0.1"
FORWARD_PORT = 65432

HEADER = "\033[95m"
OKBLUE = "\033[94m"
OKCYAN = "\033[96m"
OKGREEN = "\033[92m"
WARNING = "\033[93m"
FAIL = "\033[91m"
ENDC = "\033[0m"
BOLD = "\033[1m"
UNDERLINE = "\033[4m"

# Buffer size for receiving data
BUFFER_SIZE = 4096
DELAY = 0.5  # 0.5-second delay

message_number = 0
messages_client_to_server = []
messages_server_to_client = []


def attack_payload(payload: str, changes: int = 5) -> str:
    chars = list(payload)
    for _ in range(changes):
        index = random.randint(0, len(chars))
        chars[index % len(chars)] = random.choice("abcde1234567890")
    return "".join(chars)


# Will not be strictly a predefined list, can be a random function
DROP_CLIENT_TO_SERVER = {3, 7, 11, 12}
CHANGE_CLIENT_TO_SERVER = {2, 6, 10}
DROP_SERVER_TO_CLIENT = {1, 5, 8}
CHANGE_SERVER_TO_CLIENT = {4, 9}


def handle_client(client_socket):
    global message_number
    forward_socket = None
    try:
        # Receive data from the client
        client_data = client_socket.recv(BUFFER_SIZE)
        messages_client_to_server.append(client_data)
        if not client_data:
            print(f"{OKGREEN}[-][{time.ctime()}] No data received from client.{ENDC}")
            return

        print(f"{OKGREEN}[>][{time.ctime()}] Received from client:{ENDC} {client_data}")

        ### DROP PACKET ###
        if message_number and message_number in DROP_CLIENT_TO_SERVER:
            print(
                f"{WARNING}[X][{time.ctime()}] Dropping, returning empty string to client:{ENDC}"
            )
            client_socket.sendall(bytes())
            raise AttackException("Drop client to server")

        ### ATTACK PAYLOAD ###
        if message_number and message_number in CHANGE_CLIENT_TO_SERVER:
            client_data = attack_payload(client_data.decode("utf-8")).encode("utf-8")
            print(
                f"{WARNING}[X][{time.ctime()}] Modifying payload to:{ENDC} {client_data}"
            )

        # Forward the data to the target server
        forward_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        forward_socket.connect((FORWARD_IP, FORWARD_PORT))

        ### REPLAY A PREVIOUS ###
        REPLAY = random.randint(1, 8)
        if message_number and REPLAY < len(messages_client_to_server):
            forward_socket.sendall(messages_client_to_server[REPLAY])
            forward_socket.recv(BUFFER_SIZE)

        forward_socket.sendall(client_data)

        # Receive response from the target server
        server_response = forward_socket.recv(BUFFER_SIZE)
        messages_server_to_client.append(server_response)
        print(
            f"{OKBLUE}[<][{time.ctime()}] Received from server:{ENDC} {server_response}"
        )

        ### ATTACK RESPONSE ###
        if message_number and message_number in CHANGE_SERVER_TO_CLIENT:
            server_response = attack_payload(server_response.decode("utf-8")).encode(
                "utf-8"
            )
            print(
                f"{WARNING}[X][{time.ctime()}] Modifying payload to:{ENDC} {server_response}"
            )

        ### DROP RESPONSE ###
        if message_number and message_number in DROP_SERVER_TO_CLIENT:
            server_response = bytes()
            print(
                f"{WARNING}[X][{time.ctime()}] Modifying payload to:{ENDC} {server_response}"
            )

        # Send the response back to the client
        client_socket.sendall(server_response)

    except AttackException as e:
        print(f"[-][{time.ctime()}] MITM Attack: {e}")

    except Exception as e:
        print(f"[-][{time.ctime()}] Error occurred while handling client: {e}")
    finally:
        message_number += 1

        # Close the forward and client sockets

        if forward_socket:
            forward_socket.close()
        client_socket.close()


def mitm_proxy():
    try:
        # Create a listening socket for incoming connections
        listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listen_socket.bind((LISTEN_IP, LISTEN_PORT))
        listen_socket.listen(5)
        print(f"[*][{time.ctime()}] Listening on {LISTEN_IP}:{LISTEN_PORT}")

        while True:
            # Accept a new connection from a client
            client_socket, client_addr = listen_socket.accept()
            print(
                f"{HEADER}[+][{time.ctime()}] Accepted connection from {client_addr}{ENDC}"
            )

            # Handle the client in a separate function
            handle_client(client_socket)

    except Exception as e:
        print(f"[-][{time.ctime()}] Error occurred in proxy: {e}")
    finally:
        listen_socket.close()


if __name__ == "__main__":
    mitm_proxy()
