
import requests
import base64
import sys
import json
import time
from urllib.parse import quote

TARGET_URL = "https://crypto-assignment.dangduongminhnhat2003.workers.dev/message/send?userId=group-3"
USER_ID = "group-3"

# Global token storage to simplify sharing
current_token = None

def get_token(token = None):
    if not current_token:
        return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJTZWN1cmVDaGF0IiwiaWF0IjoxNzY1ODA0MDgyLCJleHAiOjE3NjU4MDQzODIsInN1YiI6Imdyb3VwLTMiLCJzaWQiOiI3YmViODUxODVlOTUyZjVlMjBjYTM1YmRkN2MxYmVjNzdlZGE0NTdiNWNmMDVkY2JkOWUyMTY1YzgzNWY4YzdjIiwiYWxnb3JpdGhtIjoiZWNkaF8zIiwicHVibGljS2V5Ijp7IngiOiI1MTg1ODE4NTk5Mjc2NjE5OTk4NzY3NTgxNDE3NjMzMDE3ODUwNDAxMDE0MTQxMTMxMDE2NTU0OTk0MDg4ODQ2NTAwMTUxMzU3NTY1MCIsInkiOiIxMDY2NzQzNzg2ODYzMTIwODA1MzE1NDczNDQ0OTI4NzQwMzg4OTIxNTY5OTk4Njg3NDIwNjM4NDQ2Nzk2NjUzNDQ2MDMwMzIwODYzMjAifSwiZW5jcnlwdGVkRGF0YSI6Ik5IelF5cG45TTIwSklZZjI3djdtVVZpNHRKY3NsTUhSQ29ocDJoUnBtb1ZjN3RRTFEyWjZfcGRzandtM1FwUTJfWTlPN0lrNlpMcy01cTNJblVsZTNfLUF5QnJWSlJEQm1aTnlYZWJ3enFuYnpJenNfS3ItNmlLRmpFLXJFS0E1TE1udjNjSnhkaUFzZ0QzVGEwYzVISkJnbGJWTll2QmNQb2ZGU2c2UDJVZlYzOWJ6c0NNZC1Fcm9WWHpDMUxrSk9DbVJyRkJYUmJPd3pEbnZ5WFJieHRESU16dXhEcGpSdDVFRkpPbHNGTkdTVnNGTllkVzhJZkt4NGhmNXF5amlBRU95QTEweFo2WGRnRGRUdVhwSm1mT2hFVlZfMHUyb3RVR1E4blFCT2xZVEVFVVg5Zm1vS3NGWHJqeGVIM2czIiwiY3JlYXRlZEF0IjoxNzY1ODA0MDgyMjA1LCJsYXN0QWN0aXZpdHkiOjE3NjU4MDQwODI0MDN9.tX7Tdu6NdjYxjjlaTYNQHpJ9T_1lez28803uhNlbFBs"
    # print("Getting new token...")
    payload = {"sessionToken":token,"encryptedMessage":"MAZIQgTAmsAVDinEd4sLv8C7rPKQRDDb4NAn+7VwXPg=","messageSignature":{"r":"108035993748255920003762546433102273350525537080252750838057350727709903582064","s":"82142029271470318427968155031904994241565124374471464366738509207306189246637","messageHash":"72648514530506385973159568210264880929716542974816711874952670990298863471221","algorithm":"ECDSA-P256"},"clientSignaturePublicKey":{"x":"114254678552164992937619725260119019016458065805360529205433060779530438324465","y":"17314837102311763386787454760589228472258554524863079360958833882708918480321"}}
    headers = {'X-User-Id': USER_ID}
    try:
        response = requests.post(TARGET_URL, json=payload, headers=headers)
        response.raise_for_status()
        return response.json()["sessionToken"]
    except Exception as e:
        print(f"Error getting token: {e}")
        return None


def oracle_query(ciphertext_bytes, token):
    """
    Sends a ciphertext to the oracle and returns False if the padding is invalid, True otherwise.
    """
    ciphertext_base64 = base64.b64encode(ciphertext_bytes).decode('utf-8')
    
    payload = {
        "sessionToken": token,
        "encryptedMessage": ciphertext_base64,
    }
    
    while True:
        try:
            response = requests.post(
                TARGET_URL,
                json=payload,
                headers={"x-user-id": USER_ID},
                timeout=10,
            )
            
            if response.status_code in [429, 430, 500, 502, 503, 504]:
                time.sleep(1)
                continue

            try:
                response_json = response.json()
            except requests.exceptions.JSONDecodeError:
                time.sleep(1)
                continue

            if "error" in response_json:         
                if response_json["error"] == "Invalid padding":
                    return False

            return True
        
        except requests.RequestException as e:
            # print(f"Request Error: {e}")
            time.sleep(1)
            continue



def padding_oracle_attack(ciphertext_bytes, block_size=16):
    global current_token
    # Initial token
    if not current_token:
        current_token = get_token()

    num_blocks = len(ciphertext_bytes) // block_size
    iv = ciphertext_bytes[:block_size]
    ciphertext_blocks = [ciphertext_bytes[i:i+block_size] for i in range(block_size, len(ciphertext_bytes), block_size)]
    
    plaintext = b''

    # Process each block from last to first
    for block_index in range(len(ciphertext_blocks) - 1, -1, -1):
        target_block = ciphertext_blocks[block_index]
        previous_block = ciphertext_blocks[block_index - 1] if block_index > 0 else iv
        
        decrypted_block = b''
        print(f"Attacking block {block_index + 1}...")

        intermediate_state = bytearray(block_size)

        for byte_index in range(block_size - 1, -1, -1):
            padding_value = block_size - byte_index
            
            # Prepare prefix with known intermediate values
            known_mask = bytearray(block_size)
            for i in range(byte_index + 1, block_size):
                known_mask[i] = intermediate_state[i] ^ padding_value
            
            found_byte = False
            
            # Try all 256 possibilities sequentially
            # Optimization: Try common ASCII chars first? No, just 0-255 is safe.
            for guess in range(256):
                print(f"\r DEBUG: Trying guess {guess} at byte {byte_index} with token {current_token[-16:]}", end="\r")
                
                crafted_block = bytearray(block_size)
                # Fill in the known suffix
                for i in range(byte_index + 1, block_size):
                    crafted_block[i] = known_mask[i]
                
                # Try the guess
                crafted_block[byte_index] = guess
                
                test_ciphertext = bytes(crafted_block) + target_block
                
                # Use global current_token
                is_valid = oracle_query(test_ciphertext, current_token)
                
                if is_valid:
                    # Found it!
                    current_token = get_token(token=current_token)
                    intermediate_byte = guess ^ padding_value
                    intermediate_state[byte_index] = intermediate_byte
                    
                    plaintext_byte = intermediate_byte ^ previous_block[byte_index]
                    decrypted_block = bytes([plaintext_byte]) + decrypted_block
                    
                    try:
                        char_repr = chr(plaintext_byte)
                        if not (32 <= plaintext_byte <= 126):
                            char_repr = '.'
                    except:
                        char_repr = '.'
                        
                    print(f"\nFound byte {16 - byte_index}/{block_size}: {plaintext_byte:02x} ('{char_repr}')")
                    found_byte = True
                    

                    # print("  [+] Renewing token...")
                    new_tok = get_token(token=current_token)
                    current_token = new_tok
            
            if not found_byte:
                print(f"  [!] Failed to find byte {16 - byte_index}!")
                # Should we exit or likely the intermediate state is wrong?
                # Usually means previous bytes were wrong or bad luck with block oracle.
                break
                
        plaintext = decrypted_block + plaintext

    return plaintext

if __name__ == "__main__":
    # Target ciphertext
    ciphertext_bytes_base64 = "YMQWcv9ruLHpeAam8+W33OGQIWnQ8gKf0eoALx5DD\/xgZyzA1zF1eiFPubwMx1TOdhw7aP2R\/MUxPKAzcBO8dw=="

    # Run attack
    result = padding_oracle_attack(base64.b64decode(ciphertext_bytes_base64))
    print("\nDecrypted Result (Hex):", result.hex())
    try:
        # Attempt PKCS7 unpadding
        pad = result[-1]
        if pad > 0 and pad <= 16:
            print("Decrypted Message:", result[:-pad].decode('utf-8', errors='replace'))
        else:
            print("Decrypted Message (Raw):", result.decode('utf-8', errors='replace'))
    except:
        print("Decrypted Message (Raw):", result)
