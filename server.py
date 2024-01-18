from lib import *
import socket

# Main function to run the server
def main():
    # Create a socket for the server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        # Bind the socket to an IP address and port
        server_socket.bind(("localhost", 12345))
        # Listen for incoming connections
        server_socket.listen()

        print("Server is listening for incoming connections...")

        # Accept a connection from a client
        conn, addr = server_socket.accept()

        with conn:
            print(f"Connection from {addr}")

            # Generate ephemeral server keys
            server_ephemeral_private_key, server_ephemeral_public_key = generate_ephemeral_key()

            # Send the server's ephemeral public key to the client
            conn.sendall(serialize_key(server_ephemeral_public_key))

            # Receive the client's ephemeral public key
            client_ephemeral_public_key_data = conn.recv(1024)
            client_ephemeral_public_key = deserialize_key(client_ephemeral_public_key_data)

            # Derive shared secret using ECDH
            shared_secret = derive_shared_secret(server_ephemeral_private_key, client_ephemeral_public_key)

            while True:
                # Receive and decrypt a message from the client
                encrypted_message = conn.recv(1024)
                iv, tag, cipher = encrypted_message[:16], encrypted_message[16:32], encrypted_message[32:]
                decrypted_message = decrypt(shared_secret, iv, tag, cipher)
                print(f"Received from client: {decrypted_message.decode()}")

                # Encrypt and send a message to the client
                message = input("Server: ")
                iv, tag, cipher = encrypt(shared_secret, message.encode())
                encrypted_response = iv + tag + cipher
                conn.sendall(encrypted_response)

# Run the main function if the script is executed directly
if __name__ == "__main__":
    main()
