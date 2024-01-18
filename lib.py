from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# Function to generate a pair of ephemeral private and public keys using ECC
def generate_ephemeral_key():
    private_key = ec.generate_private_key(ec.SECP521R1(), backend=default_backend())
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
def encrypt(key, plaintext):
    iv = os.urandom(16)  # Generate a random IV (Initialization Vector)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag
    return iv, tag, ciphertext

# Function to decrypt a message using AES-256-GCM
def decrypt(key, iv, tag, ciphertext):
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext