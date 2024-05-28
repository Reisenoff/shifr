# client.py
import socket
import random

# Параметры Диффи-Хеллмана
p = 23  # Простое число
g = 5   # Примитивный корень

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

    client.close()

if __name__ == "__main__":
    start_client()
