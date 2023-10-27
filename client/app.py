from flask import Flask, render_template, make_response, jsonify, request
import requests
import random
import math
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from colorama import Fore, Style
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives.asymmetric import padding

encryption_method = None

def generate_private_key():
    return random.randint(2, p - 2)

def compute_public_key(private_key):
    return (alpha ** private_key) % p

def compute_shared_secret(private_key, received_public_key):
    shared_secret = (received_public_key ** private_key) % p
    shared_secret_bytes = hashlib.sha256(str(shared_secret).encode()).digest()
    return shared_secret_bytes

p = 23
alpha = 5
server_public_key = None
shared_secret_client = None

client_private_key = generate_private_key()
client_public_key = compute_public_key(client_private_key)

def generate_prime(bits):
    while True:
        num = random.getrandbits(bits)
        if is_prime(num):
            return num

def is_prime(num):
    if num <= 1:
        return False
    if num <= 3:
        return True
    if num % 2 == 0 or num % 3 == 0:
        return False
    # 6k ± 1 rule
    i = 5
    while i * i <= num:
        if num % i == 0 or num % (i + 2) == 0:
            return False
        i += 6
    return True

def compute_modulus_and_phi(p, q):
    n = p * q
    phi_n = (p - 1) * (q - 1)
    return n, phi_n

def select_public_exponent(phi_n):
    e = random.randint(2, phi_n - 1)
    while math.gcd(e, phi_n) != 1:
        e = random.randint(2, phi_n - 1)
    return e

def calculate_private_exponent(e, phi_n):
    d = mod_inverse(e, phi_n)
    return d

def mod_inverse(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        # floor division
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

def decrypt(ciphertext, d, n):
    plaintext = []
    for char_value in ciphertext:
        decrypted_char_value = pow(char_value, d, n)
        decrypted_char = chr(decrypted_char_value)
        plaintext.append(decrypted_char)
    return ''.join(plaintext)

bits = 10

p = generate_prime(bits)
q = generate_prime(bits)
n, phi_n = compute_modulus_and_phi(p, q)
e = select_public_exponent(phi_n)
d = calculate_private_exponent(e, phi_n)

app = Flask(__name__)

@app.route('/')
def index():
    return render_template("home.html")

@app.route("/handshake", methods = ["POST"])
def handshake():
    encryption = request.form["encryption"]
    if (encryption == "symmetric"):
        global encryption_method, server_public_key, shared_secret_client
        print(Fore.LIGHTCYAN_EX, "SET ENCRYPTION METHOD TO SYMMETRIC")
        encryption_method = "symmetric"
        res = requests.post("http://localhost:5002/handshake", json = {
            "encryption": encryption,
            "p": p,
            "alpha": alpha,
            "public_key": client_public_key
        })
        print(Fore.LIGHTMAGENTA_EX, "SENT ENCRYPTION METHOD TO SERVER")
        print(Fore.GREEN, "SENT VALUE OF P TO SERVER")
        print(Fore.YELLOW, "SENT VALUE OF ALPHA TO SERVER")
        print(Fore.LIGHTCYAN_EX, "SENT PUBLIC KEY TO SERVER")
        server_public_key = res.json()["public_key"]
        print(Fore.LIGHTMAGENTA_EX, "RECEIVED SERVER PUBLIC KEY")
        shared_secret_client = compute_shared_secret(client_private_key, server_public_key)
        print(Fore.GREEN, "COMPUTED SHARED SECRET")
        print(Style.RESET_ALL)
    elif (encryption == "asymmetric"):
        print(Fore.LIGHTCYAN_EX, "SET ENCRYPTION METHOD TO ASYMMETRIC")
        encryption_method = "asymmetric"
        res = requests.post("http://localhost:5002/handshake", json = {
            "encryption": encryption,
            "e": e,
            "n": n
        })
        print(Fore.LIGHTMAGENTA_EX, "SENT ENCRYPTION METHOD TO SERVER")
        print(Fore.GREEN, "SENT VALUE OF PUBLIC EXPONENT TO SERVER")
        print(Fore.YELLOW, "SENT VALUE OF N TO SERVER")
    return render_template("message.html")

@app.route("/message", methods = ["POST"])
def message():
    plain_text = request.form["plain_text"]
    if (encryption_method == "symmetric"):
        plain_text = plain_text.encode('utf-8')
        cipher = AES.new(shared_secret_client, AES.MODE_CBC)
        message_hash = hashlib.sha256(plain_text).digest()
        plain_text = pad(plain_text, AES.block_size)
        cipher_text = cipher.encrypt(plain_text)
        print(Fore.YELLOW, "GENERATED MESSAGE HASH")
        print(Fore.LIGHTCYAN_EX, "ENCRYPTED MESSAGE")
        res = requests.post("http://localhost:5002/message", json = {
            "cipher_text": cipher_text.decode('latin-1'),
            "cipher_iv": cipher.iv.decode('latin-1'),
            "message_hash": message_hash.decode('latin-1')
        })
        print(Fore.LIGHTMAGENTA_EX, "SENT CIPHER TEXT TO SERVER")
        print(Fore.YELLOW, "SENT MESSAGE HASH TO SERVER")
        print(Fore.GREEN, "SENT CIPHER IV TO SERVER")
        print(Style.RESET_ALL)
        return make_response("<p>Message encrypted and sent successfully.</p>")
    
@app.route("/certificates", methods = ["POST"])
def certificates():
    certificate = request.files['cert']
    public_key = request.files['key']
    root = request.files['root']
    certificate.save('certificate.pem.crt')
    public_key.save('public_key.pem.key')
    root.save('root.pem')
    print(Fore.LIGHTCYAN_EX, "RECEIVED CERTIFICATES FROM SERVER")
    return jsonify(message="Certificate and key files received")

if __name__ == "__main__":
    app.run(port = 5001)