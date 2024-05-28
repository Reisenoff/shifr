# server.py
import socket
import threading
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
    if os.path.exists('server_private_key.pem') and os.path.exists('server_public_key.pem'):
        private_key = serialization.load_pem_private_key(load_key_from_file('server_private_key.pem'), password=None)
        public_key = serialization.load_pem_public_key(load_key_from_file('server_public_key.pem'))
    else:
        private_key, public_key = generate_rsa_keys()
        save_key_to_file(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ), 'server_private_key.pem')
        save_key_to_file(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ), 'server_public_key.pem')
    return private_key, public_key

def handle_client(client_socket):
    server_secret = generate_secret()
    server_public_key = compute_public_key(server_secret)

    client_public_key = int(client_socket.recv(1024).decode())
    client_socket.send(str(server_public_key).encode())

    shared_secret = compute_shared_secret(client_public_key, server_secret)
    print(f"Общий секрет: {shared_secret}")

    private_key, public_key = load_or_generate_rsa_keys()

    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    client_socket.send(pem_public_key)

    pem_client_public_key = client_socket.recv(1024)
    client_public_key = serialization.load_pem_public_key(pem_client_public_key)

    encrypted_message = client_socket.recv(1024)
    decrypted_message = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print(f"Зашифрованное сообщение от клиента: {decrypted_message.decode()}")

    client_socket.close()

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', 9999))
    server.listen(5)
    print("Сервер запущен. Ожидание подключений...")

    while True:
        client_socket, addr = server.accept()
        print(f"Подключен клиент: {addr}")
        client_handler = threading.Thread(target=handle_client, args=(client_socket,))
        client_handler.start()

if __name__ == "__main__":
    start_server()
