import os
from flask import Flask, render_template, request
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KEYS_DIR = os.path.join(BASE_DIR, 'keys')
DOCUMENTS_DIR = os.path.join(BASE_DIR, 'documents')
SIGN_DIR = os.path.join(BASE_DIR, 'sign')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate_keys', methods=['GET', 'POST'])
def generate_keys():
    if request.method == 'POST':        
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        private_key_path = os.path.join(KEYS_DIR, 'private_key.pem')
        with open(private_key_path, 'wb') as f:
            f.write(private_pem)

        public_key = private_key.public_key()

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        public_key_path = os.path.join(KEYS_DIR, 'public_key.pem')
        with open(public_key_path, 'wb') as f:
            f.write(public_pem)

        message = "Kunci privat dan publik berhasil dihasilkan di folder 'keys'."
        return render_template('generate_keys.html', message=message)
    
    return render_template('generate_keys.html')

@app.route('/create_signature', methods=['GET', 'POST'])
def create_signature():
    if request.method == 'POST':
        document = request.files['document']
        document_path = os.path.join(DOCUMENTS_DIR, document.filename)
        document.save(document_path)

        # Load private key
        private_key_path = os.path.join(KEYS_DIR, 'private_key.pem')
        with open(private_key_path, 'rb') as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
            )

        with open(document_path, 'rb') as doc_file:
            document_data = doc_file.read()

        signature = private_key.sign(
            document_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        signature_path = os.path.join(SIGN_DIR, 'signature.sig')
        with open(signature_path, 'wb') as f:
            f.write(signature)

        message = "Tanda tangan berhasil dibuat."
        return render_template('create_signature.html', message=message)
    
    return render_template('create_signature.html')

@app.route('/verify_signature', methods=['GET', 'POST'])
def verify_signature():
    if request.method == 'POST':
        document = request.files['document']
        signature = request.files['signature']
        
        document_path = os.path.join(DOCUMENTS_DIR, document.filename)
        document.save(document_path)
        
        signature_path = os.path.join(SIGN_DIR, signature.filename)
        signature.save(signature_path)

        public_key_path = os.path.join(KEYS_DIR, 'public_key.pem')
        with open(public_key_path, 'rb') as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read()
            )

        with open(document_path, 'rb') as doc_file:
            document_data = doc_file.read()

        with open(signature_path, 'rb') as sig_file:
            signature_data = sig_file.read()

        try:
            public_key.verify(
                signature_data,
                document_data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            message = "Tanda tangan valid."
        except:
            message = "Tanda tangan tidak valid."

        return render_template('verify_signature.html', message=message)
    
    return render_template('verify_signature.html')

if __name__ == '__main__':
    if not os.path.exists(KEYS_DIR):
        os.makedirs(KEYS_DIR)
    if not os.path.exists(DOCUMENTS_DIR):
        os.makedirs(DOCUMENTS_DIR)
    if not os.path.exists(SIGN_DIR):
        os.makedirs(SIGN_DIR)
    app.run(debug=True)
