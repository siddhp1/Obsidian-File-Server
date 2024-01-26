import os
import hashlib
from flask import Flask, jsonify, request, send_file
from flask_sqlalchemy import SQLAlchemy


'''
SETUP FLASK AND DB
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
 

'''
AUTHENTICATION
'''
@app.route('/auth', methods=['POST'])
def authenticate():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()

    if user:
        # Check if the hashed password matches
        hashed_password = hashlib.sha512((password + user.salt).encode('utf-8')).hexdigest()
        if hashed_password == user.password:
            return jsonify({'message': 'Authentication successful', 'salt': user.salt})
    
    return jsonify({'message': 'Authentication failed'}), 401


'''
REGISTRATION
'''
# Define the base directory for user files
BASE_DIR = 'user_vaults'
# Create the directory if it doesn't exist
if not os.path.exists(BASE_DIR):
    os.makedirs(BASE_DIR)

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    # Check if the username already exists
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
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

    return jsonify({'message': 'Registration successful'}), 201


'''
FILE MANAGEMENT
'''
@app.route('/upload', methods=['POST'])
def upload_file():
    username = request.form.get('username')
    file = request.files['file']

    # Check if the user exists
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'message': 'User not found'}), 404

    # Save the uploaded file to the user's folder
    user_folder = os.path.join(BASE_DIR, username)
    file_path = os.path.join(user_folder, file.filename)
    file.save(file_path)

    return jsonify({'message': 'File uploaded successfully'}), 201

# Endpoint for file download
@app.route('/download/<username>/<filename>', methods=['GET'])
def download_file(username, filename):
    # Check if the user exists
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'message': 'User not found'}), 404

    # Check if the file exists
    file_path = os.path.join(BASE_DIR, username, filename)
    if not os.path.exists(file_path):
        return jsonify({'message': 'File not found'}), 404

    return send_file(file_path, as_attachment=True)

'''
RUN APP
'''
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, ssl_context=('ssl_keys/cert.pem', 'ssl_keys/key.pem'), debug=True)   
