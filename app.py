import os
import hashlib
import secrets
import re
from datetime import datetime
from flask import Flask, jsonify, request, send_file
from flask_sqlalchemy import SQLAlchemy

'''
CONSTANTS
'''
# Max size of user file directory (currently 1 GB)
MAX_USER_DIR = 1000000000 


'''
SETUP FLASK, DB, AND FILE DIRECTORY
'''
# Initialize flask, sqlalchemy
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)

# Setup database model for users
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    # Hashed password
    password = db.Column(db.String(128), nullable=False)
    # Salt for file encryption
    salt = db.Column(db.String(32), nullable=False)

    def __repr__(self):
        return f"User('{self.username}')"

# Define the base directory for user files
BASE_DIR = 'user_vaults'
# Create the directory if it doesn't exist
if not os.path.exists(BASE_DIR):
    os.makedirs(BASE_DIR)
 

'''
AUTHENTICATION
'''
# Route for authenticating a user
@app.route('/auth', methods=['POST'])
def authenticate():
    # Get data from the user
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    # Check if a matching username exists
    user = User.query.filter_by(username=username).first()
    if user:
        # Check if the hashed password matches
        hashed_password = hashlib.sha512((password + user.salt).encode('utf-8')).hexdigest()
        if hashed_password == user.password:
            # Return a success message and the user's salt
            return jsonify({'message': 'Authentication successful', 'salt': user.salt})
    
    # Otherwise return an error message
    return jsonify({'message': 'Authentication failed'}), 401


'''
REGISTRATION
'''
# Route for registering a user
@app.route('/register', methods=['POST'])
def register():
    # Get data from the user
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    # Check if the username already exists
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        # Return an error message
        return jsonify({'message': 'Username already exists'}), 400

    # Generate a random salt for the user
    salt = secrets.token_hex(16)

    # Hash the password with the salt
    hashed_password = hashlib.sha512((password + salt).encode('utf-8')).hexdigest()

    # Create a new user record
    new_user = User(username=username, password=hashed_password, salt=salt)
    db.session.add(new_user)
    db.session.commit()
    
    # Create a folder for the user
    user_folder = os.path.join(BASE_DIR, username)
    os.makedirs(user_folder, exist_ok=True)

    # Return a success message
    return jsonify({'message': 'Registration successful'}), 201


'''
FILE MANAGEMENT
'''
# Route for uploading a file
@app.route('/upload', methods=['POST'])
def upload_file():
    username = request.form.get('username')
    file = request.files['file']

    # Check if the user exists
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'message': 'User not found'}), 404

    # Create a unique filename using the current date and time
    current_datetime = datetime.now().strftime('%Y%m%d%H%M%S')
    file_name = f"{current_datetime}.zip"  # Assuming the original file is a zip file

    # Save the uploaded file to the user's folder
    user_folder = os.path.join(BASE_DIR, username)
    file_path = os.path.join(user_folder, file_name)

    # Read and save the file content
    file_content = file.read()
    with open(file_path, 'wb') as new_file:
        new_file.write(file_content)

    # Check the total size of the user's directory
    total_size = get_directory_size(user_folder)

    # Specify the maximum allowed directory size in bytes
    max_directory_size = 100000000  # Change this to your desired size

    # If the total size exceeds the limit, remove the oldest files until enough space
    while total_size + len(file_content) > max_directory_size:
        remove_oldest_file(user_folder)
        total_size = get_directory_size(user_folder)

    return jsonify({'message': 'File uploaded successfully'}), 201

# Function to get the size of a directory
def get_directory_size(directory):
    total_size = 0
    for dirpath, dirnames, filenames in os.walk(directory):
        for filename in filenames:
            filepath = os.path.join(dirpath, filename)
            total_size += os.path.getsize(filepath)
    return total_size

# Function to remove the oldest file in a directory
def remove_oldest_file(directory):
    # Get the oldest file in the directory
    files = [os.path.join(directory, f) for f in os.listdir(directory)]
    oldest_file = min(files, key=os.path.getctime)

    # Remove the oldest file
    os.remove(oldest_file)

# Endpoint for file download
@app.route('/download/<username>/', methods=['GET'])
def download_latest_file(username):
    # Check if the user exists
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'message': 'User not found'}), 404

    # Get a list of files in the user's folder
    user_folder = os.path.join(BASE_DIR, username)
    files = os.listdir(user_folder)

    # Filter only files with a certain format, assuming they are named with the date and time format 'YYYYMMDDHHMMSS'
    valid_files = [file for file in files if re.match(r'\d{14}\.\w+', file)]

    if not valid_files:
        return jsonify({'message': 'No valid files found'}), 404

    # Sort files based on the date in the filename
    valid_files.sort(reverse=True)

    # Select the most recent file
    latest_file = valid_files[0]
    file_path = os.path.join(user_folder, latest_file)

    return send_file(file_path, as_attachment=True)

'''
RUN APP
'''
# Run app with SSL keys
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, ssl_context=('ssl_keys/cert.pem', 'ssl_keys/key.pem'), debug=True)