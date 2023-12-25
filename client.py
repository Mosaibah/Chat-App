import socket
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import database  # Assuming database.py is in the same directory
import threading


def publicKeyLoad(received_PublicKeySer):
    try:
        public_key = serialization.load_pem_public_key(received_PublicKeySer)
        return public_key
    except Exception as e:
        print(f"Error loading public key: {e}")
        raise

def PublicKeyEnc(public_key, message):
    try:
        msgEnc = public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return msgEnc
    except Exception as e:
        print(f"Error encrypting with public key: {e}")
        raise

def login_user():
    print("Please log in to connect to the chat server.")
    username = input("Username: ")
    password = input("Password: ")
    if database.user_login(username, password):
        print("Login successful!")
        return True
    else:
        print("Login failed. Please check your credentials.")
        return False
    
def listen_for_messages(client_socket, cipher_suite):
    while True:
        try:
            msgEnc = client_socket.recv(1024)
            if msgEnc:
                message = cipher_suite.decrypt(msgEnc).decode()
                print(f'\nNew message: {message}\nYour message: ', end='')
        except Exception as e:
            print(f"Error receiving message: {e}")
            break

# def start_chat():
#     client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     client_socket.connect(('localhost', 8003))
#     print("Connected to server.")

#     try:
#         # Generating symmetric key for encryption
#         AESKey = Fernet.generate_key()
#         cipher_suite = Fernet(AESKey)

#         recipient_id = input("Enter the recipient's client ID: ")
#         while True:
#             msg_sending = input('Enter your message: ')
#             msgEnc_sending = cipher_suite.encrypt(msg_sending.encode())

#             # Format: "recipient_id:encrypted_message"
#             full_message = f"{recipient_id}:{msgEnc_sending.decode()}"
#             client_socket.sendall(full_message.encode())

#             # Assuming echo back for demonstration
#             msgEnc = client_socket.recv(1024)
#             message = cipher_suite.decrypt(msgEnc).decode()
#             print('Received:', message)
#     except KeyboardInterrupt:
#         print("Connection closed by user.")
#     except Exception as e:
#         print(f"Error: {e}")
#     finally:
#         client_socket.close()

def start_chat():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 8004))

    # Generate symmetric key for encryption
    AESKey = Fernet.generate_key()
    cipher_suite = Fernet(AESKey)

    # Start a thread to listen for messages
    threading.Thread(target=listen_for_messages, args=(client_socket, cipher_suite), daemon=True).start()

    while True:
        msg_sending = input('Enter your message: ')
        msgEnc_sending = cipher_suite.encrypt(msg_sending.encode())

        # Send encrypted message to server (no need for recipient ID)
        client_socket.sendall(msgEnc_sending)

if login_user():
    start_chat()
else:
    print("Exiting the chat client.")
