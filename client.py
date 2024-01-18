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

# Main function to run the client
def main():
    # Create a socket for the client
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        
        # Set a timeout for the connection attempt (5 seconds)
        client_socket.settimeout(5)

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
