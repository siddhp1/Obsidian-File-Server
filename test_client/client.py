import requests
import os

BASE_URL = 'https://192.168.2.90:5000'

authenticated_user = None

def register(username, password):
    url = f'{BASE_URL}/register'
    data = {'username': username, 'password': password}
    response = requests.post(url, json=data, verify=False)
    return response.json()

def authenticate(username, password):
    url = f'{BASE_URL}/auth'
    data = {'username': username, 'password': password}
    response = requests.post(url, json=data, verify=False)
    
    global authenticated_user
    if response.status_code == 200:
        authenticated_user = username
    
    return response.json()

def upload_file(file_path):
    if not authenticated_user:
        print("Please authenticate first.")
        return

    url = f'{BASE_URL}/upload'
    files = {'file': open(file_path, 'rb')}
    data = {'username': authenticated_user}
    response = requests.post(url, files=files, data=data, verify=False)
    return response.json()

def download_file(filename):
    if not authenticated_user:
        print("Please authenticate first.")
        return

    url = f'{BASE_URL}/download/{authenticated_user}/{filename}'
    response = requests.get(url, verify=False)

    if response.status_code == 200:
        # Create a folder to store downloaded files
        download_folder = f'downloads/{authenticated_user}'
        os.makedirs(download_folder, exist_ok=True)

        file_path = os.path.join(download_folder, filename)
        with open(file_path, 'wb') as file:
            file.write(response.content)

        print(f"File '{filename}' downloaded successfully to {download_folder}")
    else:
        print(f"Failed to download file '{filename}'. Server returned: {response.json()}")

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
                file_path = os.path.abspath("test.txt")  # Provide the absolute path to "test.txt"
                upload_result = upload_file(file_path)
                print(upload_result)
            else:
                print("Please authenticate first.")
        elif choice == 4:
            if authenticated_user:
                filename = "test.txt"  # Specify the filename you want to download
                download_file(filename)
            else:
                print("Please authenticate first.")
        elif choice == 5:
            break
        else:
            print("Invalid choice")