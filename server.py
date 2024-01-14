from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import socket
import os

# Function to generate a pair of ephemeral private and public keys using ECC
def generate_ephemeral_key():
    private_key = ec.generate_private_key(
        ec.SECP521R1(), backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Function to serialize a public key to bytes
def serialize_key(key):
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

# Function to deserialize a public key from bytes
def deserialize_key(data):
    return serialization.load_pem_public_key(data, backend=default_backend())

# Function to derive a shared secret using ECDH and hash it with SHA-256
def derive_shared_secret(private_key, public_key):
    shared_secret = private_key.exchange(ec.ECDH(), public_key)
    hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
    hasher.update(shared_secret)
    return hasher.finalize()

# Function to encrypt a message using AES-256-GCM
def encrypt_message(key, plaintext):
    iv = os.urandom(16)  # Generate a random IV (Initialization Vector)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag
    return iv + tag + ciphertext

# Function to decrypt a message using AES-256-GCM
def decrypt_message(key, ciphertext):
    iv = ciphertext[:16]
    tag = ciphertext[16:32]
    ciphertext_data = ciphertext[32:]
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext_data) + decryptor.finalize()
    return plaintext

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
                decrypted_message = decrypt_message(shared_secret, encrypted_message)
                print(f"Received from client: {decrypted_message.decode()}")

                # Encrypt and send a message to the client
                message = input("Server: ")
                encrypted_response = encrypt_message(shared_secret, message.encode())
                conn.sendall(encrypted_response)

# Run the main function if the script is executed directly
if __name__ == "__main__":
    main()
