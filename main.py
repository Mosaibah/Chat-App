import crypto
import database

def main():
    # Example RSA keys generation
    private_key, public_key = crypto.generate_rsa_keys()

    # Example AES key generation
    aes_key = crypto.generate_aes_key()

    # Example User Registration
    username = input("Enter username for registration: ")
    password = input("Enter password for registration: ")
    database.register_user(username, password)

    # Example User Login
    login_username = input("Enter username for login: ")
    login_password = input("Enter password for login: ")
    if database.user_login(login_username, login_password):
        print("Login successful!")
    else:
        print("Login failed.")

    # Encrypt and Decrypt a message using RSA
    test_message = "Hello, secure world!"
    encrypted_message = crypto.rsa_encrypt(test_message, public_key)
    decrypted_message = crypto.rsa_decrypt(encrypted_message, private_key)
    print("Original:", test_message)
    print("Encrypted (RSA):", encrypted_message)
    print("Decrypted (RSA):", decrypted_message)

    # Encrypt and Decrypt a message using AES
    encrypted_message_aes = crypto.aes_encrypt(test_message, aes_key)
    decrypted_message_aes = crypto.aes_decrypt(encrypted_message_aes, aes_key)
    print("Encrypted (AES):", encrypted_message_aes)
    print("Decrypted (AES):", decrypted_message_aes)

if __name__ == "__main__":
    main()
