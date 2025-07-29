from flask import Flask, render_template, request, jsonify
from cryptography.fernet import Fernet
import rsa
import base64

app = Flask(__name__)

# RSA key pair
(public_key, private_key) = rsa.newkeys(1024)

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.get_json()
    message = data['message'].encode()

    aes_key = Fernet.generate_key()
    fernet = Fernet(aes_key)
    encrypted_message = fernet.encrypt(message)
    encrypted_aes_key = rsa.encrypt(aes_key, public_key)

    return jsonify({
        'ciphertext': base64.b64encode(encrypted_message).decode(),
        'encrypted_key': base64.b64encode(encrypted_aes_key).decode()
    })

@app.route('/decrypt', methods=['POST'])
def decrypt():
    data = request.get_json()
    encrypted_key = base64.b64decode(data['encrypted_key'])
    ciphertext = base64.b64decode(data['ciphertext'])

    aes_key = rsa.decrypt(encrypted_key, private_key)
    fernet = Fernet(aes_key)
    decrypted_message = fernet.decrypt(ciphertext).decode()

    return jsonify({'decrypted_message': decrypted_message})

if __name__ == '__main__':
    app.run(debug=True)
