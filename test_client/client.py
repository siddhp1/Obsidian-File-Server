import os
import requests
import shutil
import zipfile
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import hashlib

BASE_URL = 'https://127.0.0.1:5000'

def register(username, password):
    url = f'{BASE_URL}/register'
    data = {'username': username, 'password': password}
    response = requests.post(url, json=data, verify=False)
    return response.json()

def authenticate(username, password):
    url = f'{BASE_URL}/auth'
    data = {'username': username, 'password': password}
    response = requests.post(url, json=data, verify=False)
    return response.json()

def encrypt_file(plaintext_data, salt):
    key = salt.encode('utf-8')
    cipher = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = cipher.encrypt(nonce, plaintext_data, None)
    return nonce + ciphertext

def encrypt_directory(directory_path, salt, exceptions=[]):
    # Zip the entire directory excluding specified exceptions
    temp_zip_path = 'temp_directory.zip'
    with zipfile.ZipFile(temp_zip_path, 'w') as zipf:
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                if file not in exceptions:
                    file_path = os.path.join(root, file)
                    zipf.write(file_path, os.path.relpath(file_path, directory_path))

    # Read the zipped file and encrypt
    with open(temp_zip_path, 'rb') as zip_file:
        zip_data = zip_file.read()
        encrypted_data = encrypt_file(zip_data, salt)

    # Remove the temporary zip file
    os.remove(temp_zip_path)

    return encrypted_data

def download_and_decrypt_directory(username, salt, save_path):
    url = f'{BASE_URL}/download'
    headers = {'Username': username}
    response = requests.get(url, headers=headers, verify=False)
    encrypted_data = response.content

    # Decrypt the received directory
    decrypted_data = decrypt_file(encrypted_data, salt)

    # Save the decrypted data to the specified path
    with open(save_path, 'wb') as zip_file:
        zip_file.write(decrypted_data)

    # Extract the decrypted directory
    with zipfile.ZipFile(save_path, 'r') as zip_ref:
        zip_ref.extractall(save_path.replace('.zip', ''))

    # Remove the temporary zip file
    os.remove(save_path)

def decrypt_file(encrypted_data, salt):
    key = salt.encode('utf-8')
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    cipher = AESGCM(key)
    plaintext = cipher.decrypt(nonce, ciphertext, None)
    return plaintext

if __name__ == "__main__":
    # Register a new user
    # new_username = input("Enter a new username: ")
    # new_password = input("Enter a new password: ")
    
    # registration_result = register(new_username, new_password)
    # print(registration_result)

    # Authenticate the user
    auth_username = input("Enter your username: ")
    auth_password = input("Enter your password: ")

    authentication_result = authenticate(auth_username, auth_password)
    print(authentication_result)

    # Example of encrypting and uploading an entire directory
    directory_path = 'testdir'
    # Specify any files to exclude from the encryption
    exceptions = []
    #exceptions = ['file_to_exclude.txt', 'another_file_to_exclude.txt']

    encrypted_data = encrypt_directory(directory_path, authentication_result['salt'], exceptions)

    upload_url = f'{BASE_URL}/upload'
    headers = {'Username': auth_username}
    response = requests.post(upload_url, data=encrypted_data, headers=headers, verify=False)
    print(response.json())

    # Example of downloading and decrypting an entire directory
    download_path = 'downloaded.zip'
    download_and_decrypt_directory(auth_username, authentication_result['salt'], download_path)
    print(f'Directory downloaded and decrypted to {download_path.replace(".zip", "")}')