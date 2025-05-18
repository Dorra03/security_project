from flask import Flask, request, jsonify, send_from_directory
import os
import hashlib
import pickle
import cv2
import numpy as np
from cryptography.fernet import Fernet
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
import face_recognition
import traceback

app = Flask(__name__)

       #Configuration (DB users)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

UPLOAD_FOLDER = 'secure_uploads'

db = SQLAlchemy(app)

        # Models 
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    face_encoding = db.Column(db.LargeBinary, nullable=True)

class KeyStore(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.LargeBinary, nullable=False)

with app.app_context():
    db.create_all()

        #Utilities 
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def get_or_create_key():
    key_record = KeyStore.query.first()
    if key_record:
        return key_record.key
    new_key = Fernet.generate_key()
    key_record = KeyStore(key=new_key)
    db.session.add(key_record)
    db.session.commit()
    return new_key

def generate_file_hash(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as file:
        while chunk := file.read(4096):
            sha256.update(chunk)
    return sha256.hexdigest()

       # Routes 
@app.route('/')
def index():
    return send_from_directory(os.path.dirname(os.path.abspath(__file__)), 'index.html')

@app.route('/<filename>')
def files(filename):
    if filename.endswith(('.css', '.js')):
        return send_from_directory(os.path.dirname(os.path.abspath(__file__)), filename)
    return "Not Found", 404

        # file management APIs

@app.route('/api/encrypt', methods=['POST'])
def api_encrypt():
    try:
        key = get_or_create_key()
        fernet = Fernet(key)

        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'Empty filename'}), 400

        filename = secure_filename(file.filename)
        file_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(file_path)

        # Read original file content
        with open(file_path, 'rb') as f:
            original_data = f.read()

        # Calculate hash BEFORE encryption
        file_hash = hashlib.sha256(original_data).hexdigest()

        # Encrypt the file
        encrypted_data = fernet.encrypt(original_data)
        with open(file_path, 'wb') as f:
            f.write(encrypted_data)

        # Save the original hash
        with open(file_path + ".sha256", "w") as hash_file:
            hash_file.write(file_hash)

        return jsonify({
            'status': 'success',
            'message': 'File encrypted',
            'file': filename,
            'hash': file_hash
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

    
@app.route('/api/decrypt', methods=['POST'])
def api_decrypt():
    try:
        key = get_or_create_key()
        fernet = Fernet(key)

        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'Empty filename'}), 400

        filename = secure_filename(file.filename)
        file_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(file_path)

        with open(file_path, 'rb') as f:
            encrypted_data = f.read()
            try:
                decrypted_data = fernet.decrypt(encrypted_data)
            except Exception as e:
                return jsonify({'error': 'Decryption failed: ' + str(e)}), 400

        with open(file_path, 'wb') as f:
            f.write(decrypted_data)

        hash_file_path = file_path + ".sha256"
        integrity_verified = None
        if os.path.exists(hash_file_path):
            with open(hash_file_path, 'r') as f:
                original_hash = f.read().strip()
            current_hash = generate_file_hash(file_path)
            integrity_verified = (current_hash == original_hash)

        return jsonify({
            'status': 'success',
            'message': 'File decrypted',
            'file': filename,
            'integrity_verified': integrity_verified
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    

    #  User APIs

@app.route('/api/register', methods=['POST'])
def register():
    try:
        username = request.form.get('username')
        password = request.form.get('password')
        image = request.files.get('image')

        if not all([username, password, image]):
            return jsonify({'error': 'Missing username, password, or image'}), 400

        if User.query.filter_by(username=username).first():
            return jsonify({'error': 'Username already exists'}), 400

        img_data = image.read()
        img = cv2.imdecode(np.frombuffer(img_data, np.uint8), cv2.IMREAD_COLOR)

        if img is None:
            return jsonify({'error': 'Invalid image'}), 400

        rgb_img = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)

        encodings = face_recognition.face_encodings(rgb_img)

        if not encodings:
            return jsonify({'error': 'No face detected'}), 400

        face_encoding = encodings[0]

        new_user = User(
            username=username,
            password_hash=hash_password(password),
            face_encoding=pickle.dumps(face_encoding)  
        )
        db.session.add(new_user)
        db.session.commit()

        return jsonify({
            'status': 'success',
            'message': f'User {username} registered successfully'
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        if not all([username, password]):
            return jsonify({'error': 'Missing username or password'}), 400

        user = User.query.filter_by(username=username).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404

        if user.password_hash != hash_password(password):
            return jsonify({'error': 'Invalid password'}), 401

        return jsonify({
            'status': 'success',
            'message': f'Welcome back, {username}!'
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

import traceback
@app.route('/api/recognize', methods=['POST'])
def recognize():
    try:
        if 'image' not in request.files:
            return jsonify({'error': 'No image provided'}), 400

        image = request.files['image']
        img_data = image.read()
        img = cv2.imdecode(np.frombuffer(img_data, np.uint8), cv2.IMREAD_COLOR)

        if img is None:
            return jsonify({'error': 'Invalid image'}), 400

        rgb_img = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
        encodings = face_recognition.face_encodings(rgb_img)

        if not encodings:
            return jsonify({'error': 'No face detected'}), 400

        unknown_encoding = encodings[0]

        users = User.query.all()
        for user in users:
            try:
                known_encoding = pickle.loads(user.face_encoding)

                if not isinstance(known_encoding, np.ndarray):
                    continue  

                matches = face_recognition.compare_faces([known_encoding], unknown_encoding)
                if matches[0]:
                    return jsonify({
                        'status': 'success',
                        'user': user.username
                    })
            except Exception as e:
                continue  

        return jsonify({'status': 'fail', 'message': 'No match found'}), 404

    except Exception as e:
        return jsonify({'error': str(e), 'trace': traceback.format_exc()}), 500




    #main
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
