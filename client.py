# client.py
import socket
import random
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

def start_client():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('127.0.0.1', 9999))

    # Генерация секретного числа клиента
    client_secret = generate_secret()
    client_public_key = compute_public_key(client_secret)

    # Отправка публичного ключа клиента серверу
    client.send(str(client_public_key).encode())

    # Получение публичного ключа сервера
    server_public_key = int(client.recv(1024).decode())

    # Вычисление общего секрета
    shared_secret = compute_shared_secret(server_public_key, client_secret)
    print(f"Общий секрет: {shared_secret}")

    # Генерация RSA ключей
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    # Сериализация публичного ключа
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    client.send(pem_public_key)

    # Получение публичного ключа сервера
    pem_server_public_key = client.recv(1024)
    server_public_key = serialization.load_pem_public_key(pem_server_public_key)

    # Пример обмена зашифрованным сообщением
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
