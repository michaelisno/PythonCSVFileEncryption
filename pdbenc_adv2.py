import os
import csv
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from base64 import urlsafe_b64encode, urlsafe_b64decode
from hashlib import sha256
import json

def format_key(key_str):
    return sha256(key_str.encode()).digest()

def encrypt_data(data, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()

    encrypted = encryptor.update(padded_data) + encryptor.finalize()

    return urlsafe_b64encode(iv + encrypted).decode('utf-8')

def decrypt_data(encrypted_data, key):
    decoded_data = urlsafe_b64decode(encrypted_data)
    iv = decoded_data[:16]
    encrypted = decoded_data[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data

def initialize_file(file_name, key, headers):
    data = {"headers": headers, "rows": []}
    encrypted_data = encrypt_data(json.dumps(data).encode('utf-8'), key)
    with open(file_name, 'w') as f:
        f.write(encrypted_data)

def load_file(file_name, key):
    with open(file_name, 'r') as f:
        encrypted_data = f.read()
    return json.loads(decrypt_data(encrypted_data, key).decode('utf-8'))

def save_file(file_name, key, data):
    encrypted_data = encrypt_data(json.dumps(data).encode('utf-8'), key)
    with open(file_name, 'w') as f:
        f.write(encrypted_data)

def encrypt_row(row, row_key_str):
    row_data = json.dumps(row).encode('utf-8')
    
    row_key = format_key(row_key_str)
    
    encrypted_row = encrypt_data(row_data, row_key)
    
    return encrypted_row


def decrypt_row(encrypted_row, row_key_str):
    row_key = format_key(row_key_str)

    decrypted_data = decrypt_data(encrypted_row, row_key)

    decrypted_row = json.loads(decrypted_data.decode('utf-8'))
    return decrypted_row


def main():
    file_name = input("Enter the file name: ").strip()
    key_str = input("Enter the encryption key for the file: ").strip()
    key = format_key(key_str)

    if not os.path.exists(file_name):
        print("File does not exist. Initializing a new file.")
        headers = input("Enter column headers (comma-separated): ").strip().split(',')
        initialize_file(file_name, key, headers)
        data = {"headers": headers, "rows": []}
    else:
        try:
            data = load_file(file_name, key)
        except Exception as e:
            print("Failed to decrypt the file. Please check the key.")
            return

    while True:
        print("\nMenu:")
        print("1. Display all rows (encrypted)")
        print("2. Display a specific row")
        print("3. Add a row")
        print("4. Edit a row")
        print("5. Delete a row")
        print("6. Save and Exit")

        choice = input("Choose an option: ").strip()

        if choice == '1':
            print("\nEncrypted Rows:")
            for i, row in enumerate(data["rows"]):
                print(f"{i}: {row}")

        elif choice == '2':
            row_num = int(input("Enter the row number to display: ").strip())
            if 0 <= row_num < len(data["rows"]):
                row_key_str = input("Enter the key for this row: ").strip()
                try:
                    decrypted_row = decrypt_row(data["rows"][row_num], row_key_str)
                    print("Decrypted Row:", decrypted_row)
                except Exception:
                    print("Failed to decrypt the row. Invalid key.")
            else:
                print("Invalid row number.")

        elif choice == '3':
            row_data = input("Enter the new row (comma-separated): ").strip().split(',')
            row_key_str = input("Enter a key for this row: ").strip()
            encrypted_row = encrypt_row(row_data, row_key_str)
            data["rows"].append(encrypted_row)

        elif choice == '4':
            row_num = int(input("Enter the row number to edit: ").strip())
            if 0 <= row_num < len(data["rows"]):
                row_key_str = input("Enter the key for this row: ").strip()
                try:
                    decrypted_row = decrypt_row(data["rows"][row_num], row_key_str)
                    print("Current Row:", decrypted_row)
                    new_row = input("Enter the new row (comma-separated): ").strip().split(',')
                    encrypted_row = encrypt_row(new_row, row_key_str)
                    data["rows"][row_num] = encrypted_row
                except Exception:
                    print("Failed to decrypt the row. Invalid key.")
            else:
                print("Invalid row number.")

        elif choice == '5':
            row_num = int(input("Enter the row number to delete: ").strip())
            if 0 <= row_num < len(data["rows"]):
                row_key_str = input("Enter the key for this row: ").strip()
                try:
                    decrypted_row = decrypt_row(data["rows"][row_num], row_key_str)  # Verify the key
                    data["rows"].pop(row_num)
                    print("Row deleted successfully.")
                except Exception:
                    print("Failed to decrypt the row. Invalid key.")
            else:
                print("Invalid row number.")

        elif choice == '6':
            save_file(file_name, key, data)
            print("Data saved and encrypted successfully.")
            break

        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
