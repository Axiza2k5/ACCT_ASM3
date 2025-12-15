
import requests
import base64
import sys
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote

TARGET_URL = "https://crypto-assignment.dangduongminhnhat2003.workers.dev/message/send?userId=group-3"
USER_ID = "group-3"

# Global token storage to simplify sharing
current_token = None
PARALLEL_GUESS_BATCH = 2  # Number of parallel guesses to send

def get_token(token = None):
    if not token:
        return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJTZWN1cmVDaGF0IiwiaWF0IjoxNzY1ODA4ODYwLCJleHAiOjE3NjU4MDkxNjAsInN1YiI6Imdyb3VwLTMiLCJzaWQiOiIzYWQwYzM1OWViODU4MDZjMTViOTBmNzExODc3NDZlZGJjZTc2NmIzZDQyNzU5NzNjNDc1M2U5ZTM5Yjc3YTQwIiwiYWxnb3JpdGhtIjoiZWNkaF8zIiwicHVibGljS2V5Ijp7IngiOiIyODQ5NTU5NDAyNjQ1ODA5NDA1OTk1Mjg4OTc1NTE0OTU3Mjk2ODAxNzg2MjgzNTkxNDcwMDU4MzUyODQ2MzQxMzIzNTMwNDIzODM0MCIsInkiOiIxMTU1OTUzNjA3MDE0MDQ3OTU1MjI1NzkzOTA4NjEyNTkyNDY2NDE5ODA4OTk4ODYxODUyODMyMjU4OTE2NDgwNTQ3MDYwMTU2ODMxMjkifSwiZW5jcnlwdGVkRGF0YSI6IklybGNjWEVGSmVEdjYwODdIbFhGU1VCQ3BzdjZNelV1a1FBcDZScE9EUWVGS2FLemRfQmpJUzl5N2t0S0daU00tQTF6allpQkdqWXZzWUwzY3NOa3lLR1JwazFGcUxzY0JkamtSUTRtQVd1eUNCX3RxRHJ3SnNvWE5kTFgwYnY3LTdXVG5VY2lpM3gtYVJkY01JMnNwV050NF93bVlSRkJBUkxsQXRqX1BjNWRPOGY5Ulc0Z2I5OHM4WXlTc3YxSUg4blgwUU9neEVIM2h5YnNScXFUcGhjV1UzTV94ZkZkdHlfeTZUd3o0ZGZiTzEyZTR1N2Vaa2ZSMmJ3WGVZOU1mSmNsb25mbjUyVjRmZjVJSmE1RTFTVVZaUkEySDV1cjJQQnJoeDBYSkJpWTBEYnZHQWhjYkVpemRZTi03MVEiLCJjcmVhdGVkQXQiOjE3NjU4MDg4NjAxMjIsImxhc3RBY3Rpdml0eSI6MTc2NTgwODg2MDM2M30.g-hPykPJfudY-Uh-2Vldog6eeVy2JiVq-Jp1vTFwFBc"
    # print("Getting new token...")
    payload = {"sessionToken":token,"encryptedMessage":"MGQX4GwMtgc+2SBQwH5HWTGkzl5rHGh1bYHS2Y32iQk=","messageSignature":{"r":"100434844498918931539621415088632182419027377480244682412043633053764908941713","s":"4322233777480666872602431355286828148284378635897332159169297481463049320178","messageHash":"102235061580358138396574908587881386123486953679082475591246987653487726936046","algorithm":"ECDSA-P256"},"clientSignaturePublicKey":{"x":"77475959356485984238669208075409866067894843780826672580548579248052208423804","y":"65151871469570542249818368486322157487425303988256078435808602745832562691219"}}
    headers = {'X-User-Id': USER_ID}
    try:
        response = requests.post(TARGET_URL, json=payload, headers=headers)
        response.raise_for_status()
        return response.json()["sessionToken"]
    except Exception as e:
        # print(f"Error getting token: {e}")
        return None


def refresh_token():
    """Utility to refresh the shared session token multiple times."""
    global current_token
    new_token = get_token(token=current_token)
    current_token = new_token


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


def attempt_guess(guess, byte_index, base_block_bytes, target_block, token):
    """Executes a single oracle guess for a crafted byte value."""
    crafted_block = bytearray(base_block_bytes)
    crafted_block[byte_index] = guess
    test_ciphertext = bytes(crafted_block) + target_block
    is_valid = oracle_query(test_ciphertext, token)
    return guess if is_valid else None



def padding_oracle_attack(ciphertext_bytes, block_size=16):
    global current_token
    # Initial token
    if not current_token:
        current_token = get_token()

    iv = ciphertext_bytes[:block_size]
    ciphertext_blocks = [ciphertext_bytes[i:i+block_size] for i in range(block_size, len(ciphertext_bytes), block_size)]
    
    plaintext = b''

    with ThreadPoolExecutor(max_workers=PARALLEL_GUESS_BATCH) as executor:
        # Process each block from last to first
        for block_index in range(len(ciphertext_blocks) - 1, -1, -1):
            target_block = ciphertext_blocks[block_index]
            previous_block = ciphertext_blocks[block_index - 1] if block_index > 0 else iv
            
            decrypted_block = b''
            print(f"\nAttacking block {block_index + 1}...")

            intermediate_state = bytearray(block_size)

            for byte_index in range(block_size - 1, -1, -1):
                padding_value = block_size - byte_index
                
                # Prepare prefix with known intermediate values
                known_mask = bytearray(block_size)
                for i in range(byte_index + 1, block_size):
                    known_mask[i] = intermediate_state[i] ^ padding_value

                base_block_bytes = bytes(known_mask)
                found_guess = None

                token_snapshot = current_token
                if not token_snapshot:
                    token_snapshot = get_token()
                    current_token = token_snapshot

                for batch_start in range(0, 256, PARALLEL_GUESS_BATCH):
                    batch = list(range(batch_start, min(batch_start + PARALLEL_GUESS_BATCH, 256)))
                    print(
                        f"\rTrying guesses {batch[0]}-{batch[-1]} at byte {byte_index}",
                        end="\r",
                    )

                    future_to_guess = {
                        executor.submit(
                            attempt_guess,
                            guess,
                            byte_index,
                            base_block_bytes,
                            target_block,
                            token_snapshot,
                        ): guess
                        for guess in batch
                    }

                    for future in as_completed(future_to_guess):
                        guess_result = future.result()
                        if guess_result is not None:
                            found_guess = guess_result
                            break

                    if found_guess is not None:
                        break

                if found_guess is not None:
                    intermediate_byte = found_guess ^ padding_value
                    intermediate_state[byte_index] = intermediate_byte

                    plaintext_byte = intermediate_byte ^ previous_block[byte_index]
                    decrypted_block = bytes([plaintext_byte]) + decrypted_block

                    try:
                        char_repr = chr(plaintext_byte)
                        if not (32 <= plaintext_byte <= 126):
                            char_repr = '<non-printable>'
                    except:
                        char_repr = '<non-printable>'

                    print(f"\nFound byte {16 - byte_index}/{block_size}: {plaintext_byte:02x} ('{char_repr}')")
                    refresh_token()
                else:
                    print(f"  [!] Failed to find byte {16 - byte_index}!")
                    # Should we exit or likely the intermediate state is wrong?
                    # Usually means previous bytes were wrong or bad luck with block oracle.
                    break
                
            plaintext = decrypted_block + plaintext

    return plaintext

if __name__ == "__main__":
    # Target ciphertext
    ciphertext_bytes_base64 = "kwo5VILHFo0ypm98eyh/i7m9iETk9jUekfRr00ty8djZbHmG60SzH+1BAvJc+VlDKdewAHv+gzB/wOwvA3r0vzjCyG0RK2HwEF0n67QQ5MutN5iX6p+LrFOmE1554LubeLiHNI7+NYOKlK/TWEIu1av4v/w/rmBYHjnDvERtiEb+JpUWwluK3B/Nfa+6iYIW"

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
