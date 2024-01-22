from flask import Flask, request, send_file
from flask_httpauth import HTTPBasicAuth
from cryptography.fernet import Fernet

app = Flask(__name__)
auth = HTTPBasicAuth()
key = Fernet.generate_key()
cipher_suite = Fernet(key)

# Sample user credentials (replace with your own)
users = {
    'username': 'password',
}

@auth.verify_password
def verify_password(username, password):
    if username in users and users[username] == password:
        return username

@app.route('/')
@auth.login_required
def index():
    return "Authenticated successfully!"

@app.route('/upload', methods=['POST'])
@auth.login_required
def upload():
    file = request.files['file']
    encrypted_data = cipher_suite.encrypt(file.read())
    # Save or process the encrypted data as needed
    return "File uploaded and encrypted successfully!"

@app.route('/download')
@auth.login_required
def download():
    # Retrieve encrypted data or file from storage
    # Decrypt the data using cipher_suite.decrypt(encrypted_data)
    # Send the decrypted data as a file or process it as needed
    return send_file('path/to/decrypted/file', as_attachment=True)

if __name__ == '__main__':
    app.run(ssl_context=('cert.pem', 'key.pem'), debug=True)
