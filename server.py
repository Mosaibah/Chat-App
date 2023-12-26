import socket
import threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
import base64
import config

clients = []
client_keys = {}


def broadcast(message, sender):
    for client in clients:
        if client != sender:
            client_aes_key = client_keys[client]['aes_key']
            encrypted_msg = client_aes_key.encrypt(message)
            client.sendall(encrypted_msg)

class AESCipher:
    def __init__(self, key):
        self.key = key

    def encrypt(self, data):
        cipher = AES.new(self.key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return base64.b64encode(cipher.nonce + tag + ciphertext)

    def decrypt(self, data):
        raw = base64.b64decode(data)
        nonce, tag, ciphertext = raw[:16], raw[16:32], raw[32:]
        cipher = AES.new(self.key, AES.MODE_EAX, nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)

def handle_client(client):
    while True:
        try:
            encrypted_message = client.recv(1024)
            aes_key = client_keys[client]['aes_key']
            message = aes_key.decrypt(encrypted_message)

            broadcast(message, client)
        except:
            index = clients.index(client)
            clients.remove(client)
            del client_keys[client]
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


        client_rsa_public_key = RSA.import_key(client.recv(1024))


        aes_key = AESCipher(AES.get_random_bytes(32)) 
        client_keys[client] = {'rsa_key': client_rsa_public_key, 'aes_key': aes_key}


        rsa_cipher = PKCS1_OAEP.new(client_rsa_public_key)
        encrypted_aes_key = rsa_cipher.encrypt(aes_key.key)
        client.sendall(encrypted_aes_key)


        clients.append(client)

        thread = threading.Thread(target=handle_client, args=(client,))
        thread.start()

if __name__ == "__main__":
    start_server()
