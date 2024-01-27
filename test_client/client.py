import requests
import os
import zipfile
import shutil
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# URL of the server
BASE_URL = 'https://192.168.2.90:5000'

# Variables to store the authenticated user and the encryption key
authenticated_user = None
user_encryption_key = None

'''
REGISTRATION
'''
# Register a new user
def register(username, password):
    # Go to the registration route
    url = f'{BASE_URL}/register'
    # Send the username and password as JSON
    data = {'username': username, 'password': password}
    # Get the response from the server and return it
    response = requests.post(url, json=data, verify=False)
    return response.json()


'''
AUTHENTICATION
'''
# Function to set the encryption key for the user
def set_user_encryption_key(username, password, salt):
    global user_encryption_key
    user_encryption_key = generate_encryption_key(username, password, salt)

# Function to generate the encryption key for the user
def generate_encryption_key(username, password, salt):
    # Generate the encryption key using PBKDF2HMAC
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        salt=salt,
        iterations=100000,
        length=32,
        backend=default_backend()
    )
    # Return the encryption key
    key = kdf.derive((username + password).encode('utf-8'))
    return key

# Authenticate the user
def authenticate(username, password):
    # Go to the authentication route
    url = f'{BASE_URL}/auth'
    # Send the username and password as JSON
    data = {'username': username, 'password': password}
    # Get the response from the server
    response = requests.post(url, json=data, verify=False)
    
    # If the response is successful, set the encryption key
    global authenticated_user
    if response.status_code == 200:
        authenticated_user = username
        salt = response.json()['salt'].encode('utf-8')
        set_user_encryption_key(username, password, salt)
    return response.json()


'''
UPLOADING FILES
'''
# Function to encrypt a file
def encrypt_file(file_path, encrypted_file_path):
    # If the encryption key is not set, raise an error
    if user_encryption_key is None:
        raise ValueError("Encryption key not set. Please authenticate first.")
    
    # Read the file contents
    with open(file_path, 'rb') as f:
        plaintext = f.read()

    # Encrypt the file contents
    cipher = Cipher(algorithms.AES(user_encryption_key), modes.CFB(b'\0' * 16), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # Write the encrypted file contents to a new file
    with open(encrypted_file_path, 'wb') as f:
        f.write(ciphertext)

# Function to zip a folder
def zip_folder(folder_path, zip_path):
    # If the encryption key is not set, raise an error
    if user_encryption_key is None:
        raise ValueError("Encryption key not set. Please authenticate first.")
    
    # Zip the folder
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        for foldername, subfolders, filenames in os.walk(folder_path):
            for filename in filenames:
                file_path = os.path.join(foldername, filename)
                encrypted_file_path = file_path + '.enc'
                # Encrypt the file and add it to the zip file
                encrypt_file(file_path, encrypted_file_path)
                arcname = os.path.relpath(encrypted_file_path, folder_path)
                # Add the encrypted file to the zip file
                zip_file.write(encrypted_file_path, arcname)
                # Remove the original encrypted file
                os.remove(encrypted_file_path)
    print("Folder zipped and encrypted successfully.")

# Function to upload a file
def upload_file(folder_path):
    print("Starting file upload.")
    
    # If the user is not authenticated, raise an error
    if not authenticated_user:
        print("Please authenticate first.")
        return

    # Zip the folder
    zip_path = 'vault.zip'
    zip_folder(folder_path, zip_path)

    # Go to the upload route
    url = f'{BASE_URL}/upload'
    # Send the username as JSON
    data = {'username': authenticated_user}
    
    # Send the zip file to the server
    with open(zip_path, 'rb') as file:
        files = {'file': file}
        response = requests.post(url, files=files, data=data, verify=False)
    
    print(response.json())

    # Remove the zip file from the local machine
    os.remove(zip_path)

    return response.json()

'''
DOWNLOADING FILES
'''
# Function to decrypt a file
def decrypt_file(file_path):
    # If the encryption key is not set, raise an error
    if user_encryption_key is None:
        raise ValueError("Decryption key not set. Please authenticate first.")
    
    # Read the encrypted file contents
    with open(file_path, 'rb') as f:
        ciphertext = f.read()

    # Decrypt the file contents
    cipher = Cipher(algorithms.AES(user_encryption_key), modes.CFB(b'\0' * 16), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Write the decrypted file contents to a new file
    decrypted_file_path = os.path.splitext(file_path)[0]
    with open(decrypted_file_path, 'wb') as f:
        f.write(plaintext)

    os.remove(file_path)

# Function to unzip a folders
def unzip_folder(zip_path, extract_path):
    # If the encryption key is not set, raise an errors
    if user_encryption_key is None:
        raise ValueError("Decryption key not set. Please authenticate first.")
    
    # Unzip the folder
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(extract_path)

    # Decrypt the files
    for root, dirs, files in os.walk(extract_path):
        for file in files:
            file_path = os.path.join(root, file)
            decrypt_file(file_path)
    # Remove the zip file
    os.remove(os.path.splitext(zip_path)[0])
    print("Folder unzipped and decrypted successfully.")

# Function to download a file
def download_file(download_folder):
    # If the user is not authenticated, raise an error
    if not authenticated_user:
        print("Please authenticate first.")
        return

    # Go to the download route
    url = f'{BASE_URL}/download/{authenticated_user}/'
    response = requests.get(url, verify=False)

    # If the response is successful, download the file
    if response.status_code == 200:
        # Save the file to the local machine
        filename = f"test_vault.zip"
        file_path = os.path.join(download_folder, filename)
        with open(file_path, 'wb') as file:
            file.write(response.content)

        print(f"File downloaded successfully to {file_path}")

        # Unzip the file
        if zipfile.is_zipfile(file_path):
            print(f"File is a valid zip file.")
            unzip_folder(file_path, download_folder)
            print(f"File unzipped successfully to {download_folder}")
        else:
            print(f"File is not a valid zip file.")
    else:
        print(f"Failed to download file. Server returned: {response.json()}")

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

    # Main loop
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
                # Path of the user's Obsidian vault
                folder_path = "C:\\Users\\siddh\\Desktop\\Github Clones\\Obsidian-File-Server\\test_client\\test_vault"
                upload_result = upload_file(folder_path)
                print(upload_result)
            else:
                print("Please authenticate first.")
        elif choice == 4:
            if authenticated_user:
                download_folder = "downloads"
                download_file(download_folder)
            else:
                print("Please authenticate first.")
        elif choice == 5:
            break
        else:
            print("Invalid choice")