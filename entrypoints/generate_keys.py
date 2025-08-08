from vpn.crypto import *

if __name__ == "__main__":
    client_key, server_key = generate_keypair(), generate_keypair()

    c_priv, c_pub = serialize_key(client_key)
    s_priv, s_pub = serialize_key(server_key)

    print(f"Client Public Key: {c_pub}")
    print(f"Client Private Key: {c_priv}")
    print()
    print(f"Server Public Key: {s_pub}")
    print(f"Server Private Key: {s_priv}")
