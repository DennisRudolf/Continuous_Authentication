import os
import random
from pathlib import Path
import hashlib
import base64
from Crypto.Util import number
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from datetime import datetime, timedelta
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def commit_pedersen(p, q, g, h) -> tuple:
    if not all(isinstance(value, int) for value in [p, q, g, h]):
        raise TypeError("All input values (p, q, g, h) must be integers")

    y = number.getRandomRange(1, q - 1) 
    s = number.getRandomRange(1, q - 1) 

    if not (0 <= y < q):
        raise ValueError("Message must be between 0 and q-1")

    c = (pow(g, y, p) * pow(h, s, p)) % p 

    return c, y, s

def extract_idt_token(idt_token):
    required_keys = ['commitment', 'meta_data', 'message_singed']
    
    if not all(key in idt_token for key in required_keys):
        raise ValueError("Missing one or more required fields in idt_token")

    commitment = idt_token['commitment']
    meta_data = idt_token['meta_data']
    message_singed = idt_token['message_singed']
    
    return commitment, meta_data, message_singed

def extract_meta_data(meta_data):
    required_keys = ['p_pedersen', 'q_pedersen', 'g_pedersen', 'h_pedersen', 'time_stamp', 'name', 'socnumber']
    
    if not all(key in meta_data for key in required_keys):
        raise ValueError("Missing one or more required fields in idt_token")

    p = meta_data['p_pedersen']
    q = meta_data['q_pedersen'] 
    g = meta_data['g_pedersen'] 
    h = meta_data['h_pedersen'] 
    time_stamp = meta_data['time_stamp'] 
    
    return p, q, g, h, time_stamp

def derive_secrets(password, salt, iterations=100000):

    salt_byte = bytes.fromhex(salt)

    dklen = 68

    part1_length = 16
    part2_length = 20
    part3_length = 32

    derived_password = hashlib.pbkdf2_hmac('sha256', password.encode(), salt_byte, iterations, dklen)

    S1 = derived_password[:part1_length]
    S2 = derived_password[part1_length:part1_length + part2_length]
    S3 = derived_password[part1_length + part2_length:part1_length + part2_length + part3_length]
    
    S1_hex = S1.hex()
    S2_hex = S2.hex()
    S3_hex = S3.hex()
    
    return S1_hex, S2_hex, S3_hex

def decrypt_classifier(encrypted_filename="face_classifier_encrypted.pkl", output_filename="face_classifier_decrypted.pkl", key=None):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    encrypted_file_path = os.path.join(script_dir, encrypted_filename)
    output_file_path = os.path.join(script_dir, output_filename)

    if key is None:
        raise ValueError("Key must be provided for decryption.")

    with open(encrypted_file_path, 'rb') as infile:
        iv = infile.read(12)  # The nonce (IV) used in encryption
        tag = infile.read(16)  # The authentication tag used in encryption
        ciphertext = infile.read()  # The actual encrypted content

    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)

    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError as e:
        raise ValueError("Decryption failed or integrity check failed.") from e
    
    with open(output_file_path, 'wb') as outfile:
        outfile.write(plaintext)
    #os.remove(encrypted_file_path)

def decrypt_symmetric_key_with_S3(S3):

    script_dir = os.path.dirname(os.path.abspath(__file__))
    key_path = os.path.join(script_dir, "symmetric_key.bin")
    
    with open(key_path, "rb") as file:
        encrypted_key = file.read()
    S3_bytes = bytes.fromhex(S3)
    key = S3_bytes.ljust(32, b'\0') 

    cipher = AES.new(key, AES.MODE_ECB)

    try:
        decrypted_key = unpad(cipher.decrypt(encrypted_key), AES.block_size)
        return decrypted_key
    except ValueError as e:
        print(f"Error during decryption: {str(e)}")
        return False
    
def get_random_image_path_of_user():
    script_dir = os.path.dirname(os.path.abspath(__file__)) 
    images_dir = os.path.join(script_dir, 'Images_User', 'Jiang_Zemin')
    allowed_extensions = {".png", ".jpg", ".jpeg", ".bmp", ".gif"}

    image_files = [
        f for f in os.listdir(images_dir)
        if os.path.isfile(os.path.join(images_dir, f)) and os.path.splitext(f)[1].lower() in allowed_extensions
    ]

    if not image_files:
        raise ValueError(f"No valid images found in {images_dir}")

    random_image_file = random.choice(image_files)
    image_path = os.path.join(images_dir, random_image_file)

    return image_path

def create_bid(label_user, password):
    return label_user + password

def convert_to_int(val):
        if isinstance(val, int):
            return val
        elif isinstance(val, str):
            try:
                if val.startswith('0x') or all(c in '0123456789abcdefABCDEF' for c in val):
                    return int(val, 16)  
                else:
                    return int(val)
            except ValueError:
                raise ValueError(f"Cannot convert '{val}' to an integer")
        else:
            raise TypeError(f"Unsupported type for value '{val}'")
        
def compute_zkp_values(y, s, e, x, r, p):
        
    y, s, e, x, r, p = map(convert_to_int, [y, s, e, x, r, p])
    
    u = (y + (e * x)) % (p-1)
    v = (s + (e * r)) % (p-1)
   
    return u, v

def compute_kuser(a, x, y, b, r, s, p):
    a, x, y, b, r, s, p = map(convert_to_int, [a, x, y, b, r, s, p])
    exponent1 = x + y
    exponent2 = r + s
    kuser = (pow(a, exponent1, p) * pow(b, exponent2, p)) % p
    return kuser

def save_kuser_to_session_file(session_id, kuser):
    script_dir = os.path.dirname(os.path.abspath(__file__)) 
    session_keys_dir = os.path.join(script_dir, 'Session key') 
    if not os.path.exists(session_keys_dir):
        os.makedirs(session_keys_dir)
    session_file_path = os.path.join(session_keys_dir, f"{session_id}_key") 
    with open(session_file_path, 'w') as file:
        file.write(str(kuser))

def load_kuser_from_session_file(session_id):
    script_dir = os.path.dirname(os.path.abspath(__file__)) 
    session_keys_dir = os.path.join(script_dir, 'Session key')
    session_file_path = os.path.join(session_keys_dir, f"{session_id}_key") 
    
    if os.path.exists(session_file_path):
        with open(session_file_path, 'r') as file:
            kuser = file.read().strip()  
        return kuser
    else:
        print(f"Session key file for session ID {session_id} does not exist.")
        return None

def hash_key(original_key):
    original_key = str(original_key)
    hash_object = SHA256.new(data=original_key.encode('utf-8'))
    return hash_object.digest()

def encrypt_data_ecb(original_key, *args):
    key = hash_key(original_key)
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted_data = []
    for arg in args:
        if isinstance(arg, int):
            arg = str(arg)
        arg_bytes = arg.encode('utf-8')
        padded_data = pad(arg_bytes, AES.block_size)
        encrypted_data.append(cipher.encrypt(padded_data))
    encrypted_data_base64 = [base64.b64encode(data).decode('utf-8') for data in encrypted_data]
    return encrypted_data_base64

def decrypt_data_ecb(original_key, *encrypted_args):
    key = hash_key(original_key)
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_data = []
    for encrypted_arg in encrypted_args:
        if isinstance(encrypted_arg, int):  
            encrypted_arg = str(encrypted_arg)
        encrypted_bytes = base64.b64decode(encrypted_arg)
        decrypted_bytes = unpad(cipher.decrypt(encrypted_bytes), AES.block_size)
        decrypted_data.append(decrypted_bytes.decode('utf-8'))
    return decrypted_data