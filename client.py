import socket
import threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
import base64
import config
import database
import sys
import requests
from urlextract import URLExtract

username = ""


def authentication():
    print("Please select action")
    print("1. Login")
    print("2. Signup")
    action = input('')
    global username
    if action == "1":
        username = input("Username: ")
        password = input("Password: ")
        if database.user_login(username, password):
            print("Login successfully")
        else:
            print("wrong username or password")
            sys.exit(0)
    elif action == "2":
        username = input("Username: ")
        password = input("Password: ")
        if database.register_user(username, password):
            print("signed up successfully, and logged in")
            return True
    else:
        print("exit please, we don't like you :(")
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

# Malicious link to test the is_malicions function,
# probably shouldn't click on it though ;)
# http://onlineshopnow.site/
def is_malicious(url):
    url_scan_endpoint = "https://www.virustotal.com/api/v3/urls"
    headers = {
        "x-apikey": config.VIRUSTOTAL_API_KEY
    }
    data = {
        "url": url
    }

    # Sending the URL for scanning
    response = requests.post(url_scan_endpoint, headers=headers, data=data)
    result = response.json()

    if 'data' in result and 'id' in result['data']:
        analysis_id = result['data']['id']
        analysis_endpoint = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

        # Fetching the analysis results
        analysis_response = requests.get(analysis_endpoint, headers=headers)
        analysis_result = analysis_response.json()

        if 'data' in analysis_result and 'attributes' in analysis_result['data']:
            analysis_stats = analysis_result['data']['attributes'].get('stats', {})

            malicious_count = analysis_stats.get('malicious', 0)

            if malicious_count > 0:
                return True
    return False


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
            # Using urlextract to find URLs in the message
            extractor = URLExtract()
            urls = extractor.find_urls(message)
            malicious_url = False
            for url in urls:
                if is_malicious(url):
                    print(f"Warning: The URL {url} is malicious! It won't be sent to the user.")
                    malicious_url = True
                    break

            if not malicious_url:
                encrypted_message = aes_cipher.encrypt(f'{username}: {message}')
                client.send(encrypted_message)


receive_thread = threading.Thread(target=receive_messages)
receive_thread.start()

send_thread = threading.Thread(target=send_messages)
send_thread.start()
