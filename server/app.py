from flask import Flask, render_template, jsonify, request, send_from_directory
import requests
import random
import hashlib
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from colorama import Fore, Style
import os
from dotenv import load_dotenv

load_dotenv()

# environment variables for certificate files
CERTIFICATE_FILE = os.getenv('CERTIFICATE_FILE')
PUBLIC_KEY_FILE = os.getenv('PUBLIC_KEY_FILE')
PRIVATE_KEY_FILE = os.getenv('PRIVATE_KEY_FILE')
ROOT_FILE = os.getenv('ROOT_FILE')

encryption_method = None
decrypted_client_message = None

# Diffie Hellman key exchange helper functions
def generate_private_key():
    return random.randint(2, p - 2)

def compute_public_key(private_key):
    return (alpha ** private_key) % p

def compute_shared_secret(private_key, received_public_key):
    shared_secret = (received_public_key ** private_key) % p
    shared_secret_bytes = hashlib.sha256(str(shared_secret).encode()).digest()
    return shared_secret_bytes

# Diffie Hellman variables
p = None
alpha = None
server_private_key = None
server_public_key = None
client_public_key = None
shared_secret_server = None

# asymmetric encryption using client public key
def encrypt(message, e, n):
    ciphertext = []
    for char in message:
        char_value = ord(char)
        encrypted_char = pow(char_value, e, n)
        ciphertext.append(encrypted_char)
    return ciphertext

# asymmetric decryption using server private key
def decrypt(cipher_text, private_key):
    decrypted_message = private_key.decrypt(
        cipher_text,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_message

#RSA variables
client_public_exponent = None
client_n = None

app = Flask(__name__)

# index page
@app.route('/')
def index():
    return render_template("index.html")

# handshake - share variables/certificates
@app.route("/handshake", methods = ["POST"])
def handshake():
    request_data = json.loads(request.data.decode())
    if (request_data["encryption"] == "symmetric"):
        global p, alpha, client_public_key, server_private_key, server_public_key, client_public_key, encryption_method, shared_secret_server
        encryption_method = "symmetric"
        print(Fore.LIGHTCYAN_EX, "RECEIVED ENCRYPTION METHOD")
        print(Fore.LIGHTMAGENTA_EX, "RECEIVED VALUE OF P")
        print(Fore.GREEN, "RECEIVED VALUE OF ALPHA")
        print(Fore.YELLOW, "RECEIVED CLIENT PUBLIC KEY")
        p = request_data["p"]
        alpha = request_data["alpha"]
        client_public_key = request_data["public_key"]
        server_private_key = generate_private_key()
        server_public_key = compute_public_key(server_private_key)
        res_json = {
            "public_key": server_public_key
        }
        shared_secret_server = compute_shared_secret(server_private_key, client_public_key)
        print(Fore.LIGHTCYAN_EX, "SENDING PUBLIC KEY TO CLIENT")
        print(Fore.LIGHTMAGENTA_EX, "COMPUTED SHARED SECRET")
        print(Style.RESET_ALL)
    elif (request_data["encryption"] == "asymmetric"):
        global client_public_exponent, client_n
        encryption_method = "asymmetric"
        print(Fore.LIGHTCYAN_EX, "RECEIVED ENCRYPTION METHOD")
        print(Fore.LIGHTMAGENTA_EX, "RECEIVED CLIENT PUBLIC EXPONENT")
        print(Fore.GREEN, "RECEIVED VALUE OF N")
        client_public_exponent = request_data["e"]
        client_n = request_data["n"]
        files = {
            'cert': ('certificate.pem.cert', open(CERTIFICATE_FILE, 'rb')),
            'key': ('public.pem.key', open(PUBLIC_KEY_FILE, 'rb')),
            'root': ('root.pem', open(ROOT_FILE, 'rb'))
        }
        response = requests.post('http://localhost:5001/certificates', files=files)
        transfer_status = None
        if response.status_code == 200:
            transfer_status = True
            print(Fore.YELLOW, "CERTIFICATE AND KEY SENT TO CLIENT")
        else:
            transfer_status = False
            print(Fore.YELLOW, "CERTIFICATE AND KEY TRANSFER FAILED")
        res_json = {
            "transfer_status": transfer_status
        }
        print(Fore.LIGHTCYAN_EX, "SENDING TRANSFER STATUS TO CLIENT")
        print(Style.RESET_ALL)
    return jsonify(res_json)

# receive and decrypt message, respond to client
@app.route("/message", methods = ["POST"])
def message():
    if (encryption_method == "symmetric"):
        global decrypted_client_message
        request_data = json.loads(request.data.decode())
        print(Fore.GREEN, "RECEIVED CIPHER TEXT")
        print(Fore.YELLOW, "RECEIVED MESSAGE HASH")
        print(Fore.LIGHTCYAN_EX, "RECEIVED CIPHER IV")
        cipher_text = request_data["cipher_text"].encode('latin-1')
        cipher_iv = request_data["cipher_iv"].encode('latin-1')
        client_message_hash = request_data["message_hash"].encode('latin-1')
        decrypt_cipher = AES.new(shared_secret_server, AES.MODE_CBC, iv = cipher_iv)
        decrypted_message = unpad(decrypt_cipher.decrypt(cipher_text), AES.block_size)
        print(Fore.LIGHTMAGENTA_EX, "DECRYPTED MESSAGE")
        server_message_hash = hashlib.sha256(decrypted_message).digest()
        print(Fore.GREEN, "GENERATED MESSAGE HASH")
        if (server_message_hash == client_message_hash):
            print(Fore.YELLOW, "HASH MATCHED SUCCESSFULLY, INTEGRITY MAINTAINED")
        else:
            print(Fore.LIGHTCYAN_EX, "HASH DOES NOT MATCH, INTEGRITY BREACHED")
        decrypted_client_message = decrypted_message.decode()
        print(Style.RESET_ALL)
        res_json = {
            "response": "success"
        }
    elif (encryption_method == "asymmetric"):
        request_data = json.loads(request.data.decode())
        print(Fore.GREEN, "RECEIVED CIPHER TEXT")
        print(Fore.YELLOW, "RECEIVED MESSAGE HASH")
        cipher_text = request_data["cipher_text"].encode('latin-1')
        client_message_hash = request_data["message_hash"].encode('latin-1')
        with open('9c07820d0f6ac831c26454761500d0e6c293161a8eed6526b077ecb7e72c1100-private.pem.key', 'rb') as key_file:
            private_key = load_pem_private_key(key_file.read(), password=None, backend=default_backend())
        decrypted_message = decrypt(cipher_text, private_key)
        print(Fore.LIGHTCYAN_EX, "DECRYPTED MESSAGE WITH SERVER PRIVATE KEY")
        server_message_hash = hashlib.sha256(decrypted_message).digest()
        print(Fore.LIGHTMAGENTA_EX, "GENERATED MESSAGE HASH")
        if (server_message_hash == client_message_hash):
            print(Fore.GREEN, "HASH MATCHED SUCCESSFULLY, INTEGRITY MAINTAINED")
        else:
            print(Fore.GREEN, "HASH DOES NOT MATCH, INTEGRITY BREACHED")
        decrypted_client_message = decrypted_message.decode()
        encrypted_response = encrypt("RESPONSE FROM SERVER", client_public_exponent, client_n)
        res_json = {
            "response": encrypted_response
        }
        print(Fore.YELLOW, "RESPONDED WITH MESSAGE ENCRYPTED WITH CLIENT PUBLIC KEY")
        print(Style.RESET_ALL)
    return jsonify(res_json)

# view message
@app.route("/receive", methods = ["POST"])
def receive():
    print(Fore.LIGHTMAGENTA_EX, "READING DECRYPTED MESSAGE")
    print(Style.RESET_ALL)
    return f"Received message (decrypted): {decrypted_client_message}"

if __name__ == "__main__":
    app.run(port = 5002)