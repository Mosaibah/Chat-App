import socket
import threading
import config

clients = []

def broadcast(message, _client):
    for client in clients:
        if client != _client:
            client.sendall(message)

def handle_client(client):
    while True:
        try:
            message = client.recv(1024)
            broadcast(message, client)
        except:
            index = clients.index(client)
            clients.remove(client)
            client.close()
            break

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((config.SERVER, config.PORT))
    server.listen()

    print(f"Server started on {config.SERVER}:{config.PORT}")

    while True:
        client, addr = server.accept()
        print(f"Connected with {str(addr)}")

        clients.append(client)

        thread = threading.Thread(target=handle_client, args=(client,))
        thread.start()

if __name__ == "__main__":
    start_server()
