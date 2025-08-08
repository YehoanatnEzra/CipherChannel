import socket
import os
from vpn_server import VPN_SERVER

# Server configuration
HOST = "0.0.0.0"  # Listen on all available interfaces
PORT = 65432  # Port to listen on (non-privileged ports are > 1023)


def start_server(server: VPN_SERVER):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"Server is listening on {HOST}:{PORT}...")

        while True:
            conn, addr = s.accept()  # Accept a new connection
            with conn:
                while True:
                    data = conn.recv(1024)  # Receive data from the client
                    if not data:
                        break  # If no data is received, break out of the loop
                    response = server.receive(data.decode("utf-8"))

                    # Send acknowledgment back to the client
                    conn.sendall(response.encode("utf-8"))


if __name__ == "__main__":
    filename = os.path.join(os.path.dirname(__file__), "server_output.txt")
    output_file = open(filename, "a")
    SERVER = VPN_SERVER(output_file)
    start_server(SERVER)
