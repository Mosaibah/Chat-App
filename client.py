import socket
import threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
import base64
import config
import database
import sys


def authentication():
    ## list of actions (login, signup)
    ## switch
    ## call db
    print("Please select action")
    print("1. Login")
    print("2. Signup")
    action = input('')
    if action == "1":
        print("yes its login")
        username = input("Username: ")
        password = input("Password: ")
        if database.user_login(username, password):
            print("Login succssfully")
        else:
            print("wrong username or password")
            sys.exit(0)

        
    elif action == "2":
        print("signup yes")
        username = input("Username: ")
        password = input("Password: ")
        if database.register_user(username, password):
            print("signed up succssfully, and loged in")
            return True
        
    else:
        print("exit please, we dont like you :(")
        sys.exit(0)




def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key


class AESCipher:
    def __init__(self, key):
        self.key = key

    def encrypt(self, data):
        cipher = AES.new(self.key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data.encode('utf-8'))
        return base64.b64encode(cipher.nonce + tag + ciphertext)

    def decrypt(self, data):
        raw = base64.b64decode(data)
        nonce, tag, ciphertext = raw[:16], raw[16:32], raw[32:]
        cipher = AES.new(self.key, AES.MODE_EAX, nonce)
        return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')

print("*************** Welcome to our chat app ***************")
authentication()

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((config.SERVER, config.PORT))


private_key, public_key = generate_rsa_keys()
client.send(public_key)


encrypted_aes_key = client.recv(1024)
private_key_rsa = RSA.import_key(private_key)
cipher_rsa = PKCS1_OAEP.new(private_key_rsa)
aes_key = cipher_rsa.decrypt(encrypted_aes_key)

aes_cipher = AESCipher(aes_key)


def receive_messages():
    while True:
        try:
            encrypted_message = client.recv(1024)
            message = aes_cipher.decrypt(encrypted_message)
            print(message)
        except Exception as e:
            print(f"An error occurred: {e}")
            client.close()
            break


def send_messages():
    while True:
        message = input('')
        if message:
            encrypted_message = aes_cipher.encrypt(f'{nickname}: {message}')
            client.send(encrypted_message)


nickname = input("Choose your nickname: ")

receive_thread = threading.Thread(target=receive_messages)
receive_thread.start()

send_thread = threading.Thread(target=send_messages)
send_thread.start()
