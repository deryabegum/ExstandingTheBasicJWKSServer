from flask import Flask, jsonify, request
import jwt
import time
import sqlite3
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwcrypto import jwk

app = Flask(__name__)

# initializing the SQLite database
def init_db():
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    ''')
    cursor.execute("DELETE FROM keys")  # Clear table on startup for clean testing
    conn.commit()
    conn.close()

# storing a key in the database
def store_key(private_key, expiry):
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()
    pem_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (pem_key, expiry))
    conn.commit()
    conn.close()

# generating and storing initial keys
def initialize_keys():
    # key that expires in the past
    expired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    store_key(expired_key, int(time.time()) - 3600)  # 1 hour in the past
    
    # key that expires in the future
    valid_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    store_key(valid_key, int(time.time()) + 3600)  # 1 hour in the future

# retrieving a key from the database based on expiry
def get_key(expired):
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()
    if expired:
        cursor.execute("SELECT kid, key FROM keys WHERE exp < ?", (int(time.time()),))
    else:
        cursor.execute("SELECT kid, key FROM keys WHERE exp > ?", (int(time.time()),))
    result = cursor.fetchone()
    conn.close()
    if result:
        kid, pem_key = result
        private_key = serialization.load_pem_private_key(pem_key, password=None)
        return kid, private_key
    return None, None

# JWKS endpoint
@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()
    cursor.execute("SELECT kid, key FROM keys WHERE exp > ?", (int(time.time()),))
    keys = []
    for row in cursor.fetchall():
        kid, pem_key = row
        private_key = serialization.load_pem_private_key(pem_key, password=None)
        public_key = private_key.public_key()
        
        # converting to JWK format
        jwk_key = jwk.JWK.from_pem(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
        jwk_key_obj = jwk_key.export(as_dict=True)
        jwk_key_obj['kid'] = str(kid)  # ensuring kid is a string
        keys.append(jwk_key_obj)
    conn.close()
    return jsonify({"keys": keys}), 200

# auth endpoint to issue a JWT
@app.route('/auth', methods=['POST'])
def auth():
    expired = request.args.get('expired', 'false') == 'true'
    kid, private_key = get_key(expired)
    if private_key is None:
        return jsonify({"error": "No appropriate key found"}), 404

    expiry_time = time.time() - 3600 if expired else time.time() + 3600
    print(f"JWT kid: {kid}")
    token = jwt.encode(
        {
            'sub': 'userABC',
            'exp': expiry_time
        },
        private_key,
        algorithm='RS256',
        headers={"kid": str(kid)}  # setting 'kid' in the JWT header
    )
    return jsonify({"token": token}), 200

if __name__ == '__main__':
    init_db()  # initiazlizing the database
    initialize_keys()  # generating initial keys
    app.run(host='0.0.0.0', port=8080)
