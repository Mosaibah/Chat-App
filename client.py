import socket
import threading
import config


client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((config.SERVER, config.PORT))

def receive_messages():
    while True:
        try:
            message = client.recv(1024).decode('utf-8')
            print(message)
        except:
            print("An error occurred!")
            client.close()
            break

def send_messages():
    while True:
        message = input('')
        if message:
            formatted_message = f'{nickname}: {message}'
            client.send(formatted_message.encode('utf-8'))

nickname = input("Choose your nickname: ")

thread = threading.Thread(target=receive_messages)
thread.start()

thread = threading.Thread(target=send_messages)
thread.start()
