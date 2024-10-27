from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3
import os

hostName = "localhost"
serverPort = 8080

# Generate RSA keys
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

# Convert private key to PEM format
pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string."""
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

def insert_key_to_db(key, exp):
    """Insert a key into the SQLite database."""
    db_path = os.path.join(os.path.dirname(__file__), 'totally_not_my_privateKeys.db')
    try:
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        print(f"Inserting key with expiration: {exp}")  # Key insertion message
        c.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (key, exp))
        conn.commit()
        print("\nKey inserted successfully.\n")  # Confirmation message
    except Exception as e:
        print(f"Error inserting into database: {e}\n")  # Print error message
    finally:
        conn.close()

def insert_expired_key():
    """Insert an expired key into the database for testing."""
    expired_key = "-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----"  # Replace with actual expired key data
    exp_time = int(datetime.datetime.now().timestamp()) - 1000  # Set expiration to the past
    insert_key_to_db(expired_key, exp_time)

def get_valid_keys():
    """Retrieve all valid (non-expired) keys from the database."""
    db_path = os.path.join(os.path.dirname(__file__), 'totally_not_my_privateKeys.db')
    try:
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        current_time = int(datetime.datetime.now().timestamp())
        c.execute("SELECT key FROM keys WHERE exp > ?", (current_time,))
        keys = c.fetchall()
        print(f"\nCurrent timestamp: {current_time}, Valid keys retrieved: {len(keys)} keys.\n")  # Log count of valid keys
        return [key[0] for key in keys]
    except Exception as e:
        print(f"\nError retrieving keys: {e}\n")  # Print error message
        return []
    finally:
        conn.close()

class MyServer(BaseHTTPRequestHandler):
    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)

        if parsed_path.path == "/auth":
            headers = {
                "kid": "goodKID"
            }
            token_payload = {
                "user": "username",
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            }
            exp_time = int(token_payload["exp"].timestamp())

            if 'expired' in params:
                headers["kid"] = "expiredKID"
                token_payload["exp"] = datetime.datetime.utcnow() - datetime.timedelta(hours=1)
                exp_time = int(token_payload["exp"].timestamp())

            # Encode JWT and store it in the database
            encoded_jwt = jwt.encode(token_payload, pem, algorithm="RS256", headers=headers)
            insert_key_to_db(encoded_jwt, exp_time)

            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8"))
            return
        
        self.send_response(405)
        self.end_headers()

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            keys = get_valid_keys()
            jwks_keys = []

            for key in keys:
                jwks_keys.append({
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": "goodKID",
                    "n": int_to_base64(private_key.public_key().public_numbers().n),
                    "e": int_to_base64(private_key.public_key().public_numbers().e),
                })

            response = {"keys": jwks_keys}
            self.wfile.write(bytes(json.dumps(response), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()

if __name__ == "__main__":
    db_path = os.path.join(os.path.dirname(__file__), 'totally_not_my_privateKeys.db')
    print(f"\nConnecting to database at: {db_path}\n")  # Print database connection message
    
    # Store the PEM key in the database only once
    if not os.path.exists(db_path):
        insert_key_to_db(pem.decode(), int(datetime.datetime.utcnow().timestamp()))  # Optional
        insert_expired_key()  # Insert an expired key for testing

    print(f"Starting server on http://{hostName}:{serverPort}\n")  # Inform about the server start
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
