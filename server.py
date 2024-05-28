# server.py
import socket
import threading
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

def handle_client(client_socket):
    # Генерация секретного числа сервера
    server_secret = generate_secret()
    server_public_key = compute_public_key(server_secret)

    # Получение публичного ключа клиента
    client_public_key = int(client_socket.recv(1024).decode())

    # Отправка публичного ключа сервера клиенту
    client_socket.send(str(server_public_key).encode())

    # Вычисление общего секрета
    shared_secret = compute_shared_secret(client_public_key, server_secret)
    print(f"Общий секрет: {shared_secret}")

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
