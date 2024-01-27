import requests
import os
import zipfile
import shutil
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BASE_URL = 'https://192.168.2.90:5000'
authenticated_user = None
user_encryption_key = None


'''
REGISTRATION
'''
def register(username, password):
    url = f'{BASE_URL}/register'
    data = {'username': username, 'password': password}
    response = requests.post(url, json=data, verify=False)
    return response.json()


'''
AUTHENTICATION
'''
def set_user_encryption_key(username, password, salt):
    global user_encryption_key
    user_encryption_key = generate_encryption_key(username, password, salt)
    
def generate_encryption_key(username, password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        salt=salt,
        iterations=100000,
        length=32,
        backend=default_backend()
    )
    key = kdf.derive((username + password).encode('utf-8'))
    return key

def authenticate(username, password):
    url = f'{BASE_URL}/auth'
    data = {'username': username, 'password': password}
    response = requests.post(url, json=data, verify=False)
    
    global authenticated_user
    if response.status_code == 200:
        authenticated_user = username
        salt = response.json()['salt'].encode('utf-8')
        set_user_encryption_key(username, password, salt)
    
    return response.json()


'''
UPLOADING FILES
'''
def encrypt_file(file_path, encrypted_file_path):
    if user_encryption_key is None:
        raise ValueError("Encryption key not set. Please authenticate first.")
    
    with open(file_path, 'rb') as f:
        plaintext = f.read()

    cipher = Cipher(algorithms.AES(user_encryption_key), modes.CFB(b'\0' * 16), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    with open(encrypted_file_path, 'wb') as f:
        f.write(ciphertext)

def zip_folder(folder_path, zip_path):
    if user_encryption_key is None:
        raise ValueError("Encryption key not set. Please authenticate first.")
    
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        for foldername, subfolders, filenames in os.walk(folder_path):
            for filename in filenames:
                file_path = os.path.join(foldername, filename)
                encrypted_file_path = file_path + '.enc'
                encrypt_file(file_path, encrypted_file_path)
                arcname = os.path.relpath(encrypted_file_path, folder_path)
                zip_file.write(encrypted_file_path, arcname)
                os.remove(encrypted_file_path)
    print("Folder zipped and encrypted successfully.")

def upload_file(folder_path):
    print("Starting file upload.")
    if not authenticated_user:
        print("Please authenticate first.")
        return

    zip_path = 'vault.zip'
    zip_folder(folder_path, zip_path)

    url = f'{BASE_URL}/upload'
    data = {'username': authenticated_user}
    
    with open(zip_path, 'rb') as file:
        files = {'file': file}
        response = requests.post(url, files=files, data=data, verify=False)
        
    print(response.json())

    os.remove(zip_path)

    return response.json()

'''
DOWNLOADING FILES
'''
def decrypt_file(file_path):
    if user_encryption_key is None:
        raise ValueError("Decryption key not set. Please authenticate first.")
    
    with open(file_path, 'rb') as f:
        ciphertext = f.read()

    cipher = Cipher(algorithms.AES(user_encryption_key), modes.CFB(b'\0' * 16), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    decrypted_file_path = os.path.splitext(file_path)[0]
    with open(decrypted_file_path, 'wb') as f:
        f.write(plaintext)

    os.remove(file_path)
        
def unzip_folder(zip_path, extract_path):
    if user_encryption_key is None:
        raise ValueError("Decryption key not set. Please authenticate first.")
    
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(extract_path)

    for root, dirs, files in os.walk(extract_path):
        for file in files:
            file_path = os.path.join(root, file)
            decrypt_file(file_path)
    os.remove(os.path.splitext(zip_path)[0])
    print("Folder unzipped and decrypted successfully.")

def download_file(filename, download_folder):
    if not authenticated_user:
        print("Please authenticate first.")
        return

    url = f'{BASE_URL}/download/{authenticated_user}/{filename}'
    response = requests.get(url, verify=False)

    if response.status_code == 200:
        zip_path = os.path.join(download_folder, filename)
        with open(zip_path, 'wb') as file:
            file.write(response.content)

        print(f"File '{filename}' downloaded successfully to {download_folder}")

        if zipfile.is_zipfile(zip_path):
            print(f"File '{filename}' is a valid zip file.")
            unzip_folder(zip_path, download_folder)

            print(f"File '{filename}' unzipped successfully to {download_folder}")
        else:
            print(f"File '{filename}' is not a valid zip file.")
    else:
        print(f"Failed to download file '{filename}'. Server returned: {response.json()}")


'''
MAIN LOOP
'''
if __name__ == "__main__":
    prompt = """
1. Register
2. Login
3. Upload File
4. Download File
5. Exit
-> """

    while True:
        choice = int(input(prompt))
        if choice == 1:
            username = input("Enter a new username: ")
            password = input("Enter a new password: ")
            registration_result = register(username, password)
            print(registration_result)
        elif choice == 2:
            username = input("Enter your username: ")
            password = input("Enter your password: ")
            authentication_result = authenticate(username, password)
            print(authentication_result)
        elif choice == 3:
            if authenticated_user:
                folder_path = "C:\\Users\\siddh\\Desktop\\Github Clones\\Obsidian-File-Server\\test_client\\test_vault"
                upload_result = upload_file(folder_path)
                print(upload_result)
            else:
                print("Please authenticate first.")
        elif choice == 4:
            if authenticated_user:
                filename = "vault.zip"
                download_folder = "downloads"
                download_file(filename, download_folder)
            else:
                print("Please authenticate first.")
        elif choice == 5:
            break
        else:
            print("Invalid choice")