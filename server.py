import socket
import threading
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

def RSAKeyGen():
    try:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
        return private_key, public_key
    except Exception as e:
        print(f"Error generating RSA key pair: {e}")
        raise

def PublicKeySer(public_key):
    try:
        serialized_public_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM, 
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return serialized_public_key
    except Exception as e:
        print(f"Error serializing public key: {e}")
        raise

def PrivKeyDecrypt(private_key, msgEnc):
    try:
        msgDec = private_key.decrypt(
            msgEnc,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return msgDec
    except Exception as e:
        print(f"Error decrypting with private key: {e}")
        raise

# ... [Imports and RSAKeyGen, PublicKeySer definitions]

# def handle_client(connection, clients):
#     while True:
#         try:
#             msg = connection.recv(1024)
#             if not msg:
#                 break

#             # Message format: "recipient_id:message"
#             recipient_id, encrypted_message = msg.decode().split(':', 1)
#             if recipient_id in clients:
#                 print(f"Forwarding message to {recipient_id}...")
#                 clients[recipient_id].sendall(encrypted_message.encode())
#                 print(f"Message forwarded to {recipient_id}.")
#         except Exception as e:
#             print(f"Error: {e}")
#             break

#     connection.close()
    
chat_room = {}

def handle_client(connection):
    while True:
        try:
            msg = connection.recv(1024)
            if not msg:
                break
            
            # Broadcast message to all clients in the room
            for client_conn in chat_room.values():
                if client_conn != connection:  # Don't send message back to the sender
                    client_conn.sendall(msg)
        except Exception as e:
            break

    # Remove client from room on disconnect
    for client_id, client_conn in chat_room.items():
        if client_conn == connection:
            del chat_room[client_id]
            break
    connection.close()

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 8004))
    server_socket.listen(5)

    try:
        while True:
            connection, _ = server_socket.accept()
            # Add client to the chat room
            chat_room[str(connection)] = connection

            client_thread = threading.Thread(target=handle_client, args=(connection,))
            client_thread.start()
    except KeyboardInterrupt:
        print("Server is shutting down.")
    finally:
        server_socket.close()
start_server()

# Main server setup
# clients = {}  # Dictionary to keep track of connected clients

# server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# server_socket.bind(('localhost', 8003))
# server_socket.listen(5)

# print("Server is listening for connections...")

# try:
#     while True:
#         connection, client_address = server_socket.accept()
#         client_id = str(client_address)  # Client identifier
#         clients[client_id] = connection

#         print(f"Client connected: {client_address}")
#         client_thread = threading.Thread(target=handle_client, args=(connection, clients))
#         client_thread.start()
# except KeyboardInterrupt:
#     print("Server is shutting down.")
# finally:
#     server_socket.close()
