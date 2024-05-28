# client.py
import socket
import random
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# Параметры Диффи-Хеллмана
p = 23
g = 5

def generate_secret():
    return random.randint(1, p-1)

def compute_public_key(secret):
    return pow(g, secret, p)

def compute_shared_secret(public_key, secret):
    return pow(public_key, secret, p)

def save_key_to_file(key, filename):
    with open(filename, 'wb') as file:
        file.write(key)

def load_key_from_file(filename):
    with open(filename, 'rb') as file:
        return file.read()

def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

def load_or_generate_rsa_keys():
    if os.path.exists('client_private_key.pem') and os.path.exists('client_public_key.pem'):
        private_key = serialization.load_pem_private_key(load_key_from_file('client_private_key.pem'), password=None)
        public_key = serialization.load_pem_public_key(load_key_from_file('client_public_key.pem'))
    else:
        private_key, public_key = generate_rsa_keys()
        save_key_to_file(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ), 'client_private_key.pem')
        save_key_to_file(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ), 'client_public_key.pem')
    return private_key, public_key

def start_client():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('127.0.0.1', 9999))

    client_secret = generate_secret()
    client_public_key = compute_public_key(client_secret)

    client.send(str(client_public_key).encode())

    server_public_key = int(client.recv(1024).decode())

    shared_secret = compute_shared_secret(server_public_key, client_secret)
    print(f"Общий секрет: {shared_secret}")

    private_key, public_key = load_or_generate_rsa_keys()

    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    client.send(pem_public_key)

    pem_server_public_key = client.recv(1024)
    server_public_key = serialization.load_pem_public_key(pem_server_public_key)

    message = b"Hello, secure world!"
    encrypted_message = server_public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    client.send(encrypted_message)

    client.close()

if __name__ == "__main__":
    start_client()
