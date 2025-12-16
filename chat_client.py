import requests
import json
import base64
import hashlib
import os
import sys
import time

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding

# Constants
BASE_URL = "https://crypto-assignment.dangduongminhnhat2003.workers.dev"
USER_ID = "group-3"
CURVE_ORDER = 115792089210356248762697446949407573529996955224135760342422259061068512044369

LAST_REQUEST_TIME = 0

def enforce_rate_limit():
    global LAST_REQUEST_TIME
    current_time = time.time()
    elapsed = current_time - LAST_REQUEST_TIME
    if elapsed < 1:
        time.sleep(1 - elapsed)
    LAST_REQUEST_TIME = time.time()

class CryptoManager:
    def __init__(self):
        # 1. Generate ECDH Key Pair (for encryption/decryption)
        self.ecdh_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        self.ecdh_public_key = self.ecdh_private_key.public_key()
        
        # 2. Generate ECDSA Key Pair (for signing)
        self.ecdsa_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        self.ecdsa_public_key = self.ecdsa_private_key.public_key()
        
        self.shared_secret = None
        self.aes_key = None

    def get_public_key_xy(self, public_key):
        numbers = public_key.public_numbers()
        return str(numbers.x), str(numbers.y)

    def derive_shared_secret(self, server_public_key_x, server_public_key_y):
        try:
            # Reconstruct server public key
            server_public_numbers = ec.EllipticCurvePublicNumbers(
                int(server_public_key_x),
                int(server_public_key_y),
                ec.SECP256R1()
            )
            server_public_key = server_public_numbers.public_key(default_backend())
            
            # Perform ECDH
            self.shared_secret = self.ecdh_private_key.exchange(ec.ECDH(), server_public_key)
            
            # Derive AES Key using PBKDF2HMAC (matches chat.py)
            salt = b'\x00' * 16
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=1000,
                backend=default_backend()
            )
            self.aes_key = kdf.derive(self.shared_secret)
            
            return True
        except Exception as e:
            print(f"Error deriving shared secret: {e}")
            return False

    def sign_message(self, message_bytes):
        # Sign the hash of the message
        # We need to return r, s, and the hash
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(message_bytes)
        message_hash = digest.finalize()
        
        signature = self.ecdsa_private_key.sign(
            message_bytes,
            ec.ECDSA(hashes.SHA256())
        )
        
        r, s = decode_dss_signature(signature)
        
        # Match chat.py: hash int modulo order
        msg_hash_int = int.from_bytes(message_hash, byteorder='big') % CURVE_ORDER
        
        return str(r), str(s), str(msg_hash_int)

    def verify_signature(self, public_key_x, public_key_y, message_bytes, r, s):
        try:
            public_numbers = ec.EllipticCurvePublicNumbers(
                int(public_key_x),
                int(public_key_y),
                ec.SECP256R1()
            )
            public_key = public_numbers.public_key(default_backend())
            
            signature = encode_dss_signature(int(r), int(s))
            
            public_key.verify(
                signature,
                message_bytes,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except Exception as e:
            print(f"Signature verification failed: {e}")
            return False

    def encrypt_message(self, plaintext):
        if not self.aes_key:
            raise ValueError("AES key not derived yet.")
            
        # AES CBC Encryption
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.aes_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # PKCS7 Padding using library
        padder = padding.PKCS7(128).padder()
        padded_plaintext = padder.update(plaintext.encode('utf-8')) + padder.finalize()
        
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
        
        # Format: Base64(IV + Ciphertext)
        # Format: Base64(IV + Ciphertext)
        return base64.b64encode(iv + ciphertext).decode('utf-8')

    def decrypt_message(self, encrypted_b64):
        if not self.aes_key:
            raise ValueError("AES key not derived yet.")
            
        data = base64.b64decode(encrypted_b64)
        iv = data[:16]
        ciphertext = data[16:]
        
        cipher = Cipher(algorithms.AES(self.aes_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        
        return plaintext.decode('utf-8')

class ChatAPI:
    def __init__(self, crypto_manager):
        self.crypto = crypto_manager
        self.session_token = None
        self.client_signature_public_key_xy = self.crypto.get_public_key_xy(self.crypto.ecdsa_public_key)

    def create_session(self):
        print("Creating session...")
        url = f"{BASE_URL}/session/create?userId={USER_ID}"
        headers = {"Content-Type": "application/json"}
        data = {"algorithm": "ecdh_3"}
        
        try:
            enforce_rate_limit()
            response = requests.post(url, headers=headers, json=data)
            response.raise_for_status()
            res_json = response.json()
            
            if res_json.get("success"):
                self.session_token = res_json.get("sessionToken")
                server_pub_key = res_json.get("serverPublicKey")
                if server_pub_key:
                    self.crypto.derive_shared_secret(server_pub_key["x"], server_pub_key["y"])
                
                print("Session created successfully.")
                return True
            else:
                print(f"Failed to create session: {res_json}")
                return False
        except Exception as e:
            print(f"Error creating session: {e}")
            return False

    def exchange_keys(self):
        print("Exchanging keys...")
        if not self.session_token:
            print("No session token available.")
            return False
            
        url = f"{BASE_URL}/session/exchange?userId={USER_ID}"
        headers = {"Content-Type": "application/json"}
        
        # Prepare client public key
        client_pub_x, client_pub_y = self.crypto.get_public_key_xy(self.crypto.ecdh_public_key)
        
        sign_payload = f'{{"x":"{client_pub_x}","y":"{client_pub_y}"}}'.encode('utf-8')
        
        r, s, msg_hash = self.crypto.sign_message(sign_payload)
        
        data = {
            "sessionToken": self.session_token,
            "clientPublicKey": {
                "x": client_pub_x,
                "y": client_pub_y
            },
            "clientPublicKeySignature": {
                "r": r,
                "s": s,
                "messageHash": msg_hash,
                "algorithm": "ECDSA-P256"
            },
            "clientSignaturePublicKey": {
                "x": self.client_signature_public_key_xy[0],
                "y": self.client_signature_public_key_xy[1]
            }
        }
        
        try:
            enforce_rate_limit()
            response = requests.post(url, headers=headers, json=data)
            # response.raise_for_status() # Don't raise yet, check body
            res_json = response.json()
            
            if response.status_code == 200 and res_json.get("success"):
                # Update session token if provided (it usually rotates)
                if "sessionToken" in res_json:
                    self.session_token = res_json["sessionToken"]
                print("Key exchange successful.")
                return True
            else:
                print(f"Key exchange failed: {response.text}")
                return False
        except Exception as e:
            print(f"Error during key exchange: {e}")
            return False

    def send_message(self, message):
        url = f"{BASE_URL}/message/send?userId={USER_ID}"
        headers = {
            "Content-Type": "application/json",
            "X-User-Id": USER_ID
        }
        
        encrypted_msg_b64 = self.crypto.encrypt_message(message)
        
        # Payload to sign: The Base64 string of the encrypted message
        sign_payload = encrypted_msg_b64.encode('utf-8')

        r, s, msg_hash = self.crypto.sign_message(sign_payload)
        
        data = {
            "sessionToken": self.session_token,
            "encryptedMessage": encrypted_msg_b64,
            "messageSignature": {
                "r": r,
                "s": s,
                "messageHash": msg_hash, # This is the integer representation of the hash
                "algorithm": "ECDSA-P256"
            },
            "clientSignaturePublicKey": {
                "x": self.client_signature_public_key_xy[0],
                "y": self.client_signature_public_key_xy[1]
            }
        }
        
        try:
            # print("Sending encrypted message...")
            enforce_rate_limit()
            response = requests.post(url, headers=headers, json=data)
            # print(f"Response Status: {response.status_code}")
            res_json = response.json()
            
            if response.status_code == 200:
                # Update token
                self.session_token = res_json["sessionToken"]

                # Verify Signature
                if "responseSignature" in res_json and "serverSignaturePublicKey" in res_json:
                    resp_sig = res_json["responseSignature"]
                    server_sig_pub = res_json["serverSignaturePublicKey"]
                    enc_resp = res_json.get("encryptedResponse")
                    
                    if enc_resp:
                        is_valid = self.crypto.verify_signature(
                            server_sig_pub["x"],
                            server_sig_pub["y"],
                            enc_resp.encode('utf-8'),
                            resp_sig["r"],
                            resp_sig["s"]
                        )
                        
                        if is_valid:
                            print("Server signature verified.")
                        else:
                            print("WARNING: Server signature verification FAILED!")
                    
                # Decrypt response
                enc_resp = res_json.get("encryptedResponse")
                if enc_resp:
                    try:
                        decrypted = self.crypto.decrypt_message(enc_resp)
                        print(f"Bot: {decrypted}")
                    except Exception as e:
                        print(f"Bot (raw): {json.dumps(res_json, indent=2)}")
                        print(f"Error decrypting response: {e}")
                else:
                    print(f"Bot: {json.dumps(res_json, indent=2)}")
                    
                return True
            else:
                print(f"Failed to send message: {response.text}")
                return False
        except Exception as e:
            print(f"Error sending message: {e}")
            return False

    def delete_session(self):
        print("Deleting session...")
            
        url = f"{BASE_URL}/session/delete?userId={USER_ID}"
        headers = {"Content-Type": "application/json"}
        data = {"sessionToken": self.session_token}
        
        try:
            enforce_rate_limit()
            response = requests.post(url, headers=headers, json=data)
            res_json = response.json()
            
            if response.status_code == 200 and res_json.get("success"):
                print("Session deleted successfully.")
                self.session_token = None
                return True
            else:
                print(f"Failed to delete session: {res_json}")
                return False
        except Exception as e:
            print(f"Error deleting session: {e}")
            return False

def main():
    cm = CryptoManager()
    api = ChatAPI(cm)
    
    if not api.create_session():
        print("Aborting.")
        return
        
    if not api.exchange_keys():
        print("Aborting.")
        return
        
    print("\n--- Chat Started ---\nType 'exit' to quit.\n")
    while True:
        try:
            user_input = input("You: ")
            if user_input.lower() in ['exit', 'quit']:
                api.delete_session()
                break
            
            api.send_message(user_input)
            
        except KeyboardInterrupt:
            api.delete_session()
            break
            
    print("\nChat ended.")

if __name__ == "__main__":
    main()
