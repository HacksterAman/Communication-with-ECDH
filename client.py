from temp import *
import socket

# Main function to run the client
def main():
    # Create a socket for the client
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:

        try:
            # Attempt to connect to the server
            client_socket.connect(("localhost", 12345))
        except socket.timeout:
            print("Connection attempt timed out.")
            return
        except ConnectionRefusedError:
            print("Connection refused. The target machine is not accepting connections.")
            return
        except Exception as e:
            print(f"Connection failed: {e}")
            return

        print("Connected to the server.")

        # Generate ephemeral client keys
        client_ephemeral_private_key, client_ephemeral_public_key = generate_ephemeral_key()

        # Send the client's ephemeral public key to the server
        client_socket.sendall(serialize_key(client_ephemeral_public_key))

        # Receive the server's ephemeral public key
        server_ephemeral_public_key_data = client_socket.recv(1024)
        server_ephemeral_public_key = deserialize_key(server_ephemeral_public_key_data)

        # Derive shared secret using ECDH
        shared_secret = derive_shared_secret(client_ephemeral_private_key, server_ephemeral_public_key)

        while True:
            # Encrypt and send a message to the server
            message = input("Client: ")
            encrypted_message = encrypt_message(shared_secret, message.encode())
            client_socket.sendall(encrypted_message)

            # Receive and decrypt a message from the server
            encrypted_response = client_socket.recv(1024)
            decrypted_response = decrypt_message(shared_secret, encrypted_response)
            print(f"Received from server: {decrypted_response.decode()}")

# Run the main function if the script is executed directly
if __name__ == "__main__":
    main()
