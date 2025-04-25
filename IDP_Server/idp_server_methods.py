import os
import random
from pathlib import Path
import hashlib
import base64
import csv
import secrets
from Crypto.Util import number
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from datetime import datetime, timedelta, timezone
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import binascii
import uuid
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TRAINING_DATA_DIR = os.path.join(BASE_DIR, "Training_Data")
KEY_FILE = os.path.join(BASE_DIR, "private_key.pem")

def choose_training_persons(amount_people=30):
    folder_path = Path(TRAINING_DATA_DIR)
    folder_names = [subdir.name for subdir in folder_path.iterdir() if subdir.is_dir()]
    chosen_folders = random.sample(folder_names, min(amount_people, len(folder_names)))
    return chosen_folders

def derive_secrets(password, iterations=100000):

    dklen = 68
    salt = secrets.token_bytes(16)

    part1_length = 16
    part2_length = 20
    part3_length = 32

    derived_password = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations, dklen)

    S1 = derived_password[:part1_length]
    S2 = derived_password[part1_length:part1_length + part2_length]
    S3 = derived_password[part1_length + part2_length:part1_length + part2_length + part3_length]
    
    S1_hex = S1.hex()
    S2_hex = S2.hex()
    S3_hex = S3.hex()
    salt_hex = salt.hex()
    
    return S1_hex, S2_hex, S3_hex, salt_hex

def initialize_pedersen(bit_length=512):
    q = number.getPrime(bit_length) 
    p = 2 * q + 1               
    while not number.isPrime(p):     
        q = number.getPrime(bit_length)
        p = 2 * q + 1

    g = number.getRandomRange(1, p - 1)
    while pow(g, q, p) != 1:
        g = number.getRandomRange(1, p - 1)
    s = number.getRandomRange(1, q - 1)
    h = pow(g, s, p)

    return p, q, g, h

def commit_pedersen(m_hex, r_hex, p, q, g, h) -> tuple:
    m = int(m_hex, 16)
    r = int(r_hex, 16)

    if not (0 <= m < q):
        raise ValueError("Message must be between 0 and q-1")
    if not (0 <= r < q):
        raise ValueError("Message must be between 0 and q-1")
    
    c = (pow(g, m, p) * pow(h, r, p)) % p 

    return c
    
def generate_e_w(q, only_e=False):

    e = number.getRandomRange(1, q - 1)
    if only_e:
        return e
    w = number.getRandomRange(1, q - 1) 
    return e, w   

def generate_a_b(g,h,p,w):
    a = pow(g,w,p)
    b = pow(h,w,p)

    return a,b

def bytes_to_hex(byte_data):
    return binascii.hexlify(byte_data).decode('utf-8')   

def concatenate_message(commitment, meta_data, message_singed):
    dict_for_idt = {}

    dict_for_idt['commitment'] = commitment
    dict_for_idt['meta_data'] = meta_data
    dict_for_idt['message_singed'] = bytes_to_hex(message_singed) if isinstance(message_singed, bytes) else message_singed
    
    return dict_for_idt

def extract_idt_token(idt_token):
    required_keys = ['commitment', 'meta_data', 'message_singed']
    
    if not all(key in idt_token for key in required_keys):
        raise ValueError("Missing one or more required fields in idt_token")

    commitment = idt_token['commitment']
    meta_data = idt_token['meta_data']
    message_singed = idt_token['message_singed']
    
    return commitment, meta_data, message_singed

def load_key():

    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as key_file:
            key = RSA.import_key(key_file.read())
    else:
        print("Error, key not found")
    return key

def sign_message(commitment, g, h, p, q, time_stamp, name, socnumber):
    key = load_key()

    message = (str(commitment) + str(g) + str(h) + str(p) + str(q) + time_stamp + str(name) + str(socnumber)).encode('utf-8')

    hash_obj = SHA256.new(message)
    signature = pkcs1_15.new(key).sign(hash_obj)
    return signature

def verify_signature(commitment, g, h, p, q, time_stamp, signature, name, socnumber):

    key = load_key()

    message = (str(commitment) + str(g) + str(h) + str(p) + str(q) + time_stamp + str(name) + str(socnumber)).encode('utf-8')
    if isinstance(signature, str):  
        signature = binascii.unhexlify(signature) 
    hash_obj = SHA256.new(message)
    try:
        pkcs1_15.new(key.publickey()).verify(hash_obj, signature)
        return True
    except (ValueError, TypeError):
        return False

def create_bid(label_user, password):
    return label_user + password

def create_meta_data(p, q, g, h, time_stamp, name, socnumber):
    dict_for_meta_data = {}

    dict_for_meta_data['p_pedersen'] = p
    dict_for_meta_data['q_pedersen'] = q
    dict_for_meta_data['g_pedersen'] = g
    dict_for_meta_data['h_pedersen'] = h
    dict_for_meta_data['time_stamp'] = time_stamp
    dict_for_meta_data['name'] = name
    dict_for_meta_data['socnumber'] = socnumber
    
    
    return dict_for_meta_data

def create_time_stamp(hours=None):
    today = datetime.now()
    if hours is None:
        future_date = today + timedelta(days=2*365)
    else:
        future_date = today + timedelta(hours=hours)
    
    timestamp = future_date.strftime("%Y-%m-%d %H:%M:%S")
    return timestamp

def is_timestamp_not_expired(timestamp):
    current_time = datetime.now()
    timestamp_datetime = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
    if timestamp_datetime < current_time:
        return False
    else:
        return True
   
def generate_symmetric_key(key_size=32):
    return os.urandom(key_size)

def encrypt_file(input_file_path, output_file_path, key):
    iv = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)

    with open(input_file_path, 'rb') as infile:
        plaintext = infile.read()
    
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    
    with open(output_file_path, 'wb') as outfile:
        outfile.write(iv)
        outfile.write(tag)
        outfile.write(ciphertext)

def encrypt_classifier(S3):
    key = generate_symmetric_key()
    current_dir = os.path.dirname(os.path.abspath(__file__))
    input_file = os.path.join(current_dir, 'face_classifier.pkl')
    output_file = os.path.join(current_dir, 'face_classifier_encrypted.pkl')
    key_file = os.path.join(current_dir, 'symmetric_key.bin')

    encrypt_file(input_file, output_file, key)
    encrypted_key = encrypt_symmetric_key_with_S3(key, S3)

    with open(key_file, 'wb') as keyfile:
        keyfile.write(encrypted_key)

    os.remove(input_file)

def encrypt_symmetric_key_with_S3(symmetric_key, S3):
    S3_bytes = bytes.fromhex(S3)
    key = S3_bytes.ljust(32, b'\0')

    cipher = AES.new(key, AES.MODE_ECB) 
    encrypted_key = cipher.encrypt(pad(symmetric_key, AES.block_size))

    return encrypted_key

def extract_meta_data(meta_data):
    required_keys = ['p_pedersen', 'q_pedersen', 'g_pedersen', 'h_pedersen', 'time_stamp', 'name', 'socnumber']
    
    if not all(key in meta_data for key in required_keys):
        raise ValueError("Missing one or more required fields in idt_token")

    p = meta_data['p_pedersen']
    q = meta_data['q_pedersen'] 
    g = meta_data['g_pedersen'] 
    h = meta_data['h_pedersen'] 
    time_stamp = meta_data['time_stamp'] 
    name = meta_data['name']
    socnumber = meta_data['socnumber']
    
    return p, q, g, h, time_stamp, name, socnumber

def save_auth_values(session_id, p, q, g, h, d, C, e, w, session_timer, timestamp_nizkp):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    csv_file = os.path.join(script_dir, 'auth_sessions.csv')
    file_exists = os.path.exists(csv_file)

    with open(csv_file, mode='a', newline='') as file:
        writer = csv.writer(file)
        if not file_exists:
            writer.writerow(['session_id', 'p', 'q', 'g', 'h', 'd', 'C', 'e', 'w', 'session_timer', 'timestamp_nizkp'])
        row = [session_id, p, q, g, h, d, C, e, w, session_timer, timestamp_nizkp]
        row = ["" if value is None else value for value in row]

        writer.writerow(row)

def load_auth_values(session_id, only_q=False, only_session_timer=False):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    csv_file = os.path.join(script_dir, 'auth_sessions.csv')
    
    with open(csv_file, mode='r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            if row['session_id'] == session_id:
                if only_q and only_session_timer:
                    return int(row['q']), row['session_timer']
                elif only_q:
                    return int(row['q'])
                elif only_session_timer:
                    return row['session_timer']
                return (
                    int(row['p']), int(row['q']), int(row['g']), int(row['h']), 
                    row['d'], row['C'], int(row['e']), int(row['w']), row['session_timer'], row['timestamp_nizkp']
                )
    raise ValueError(f"Session ID {session_id} not found")


def generate_unique_session_id():
    return str(uuid.uuid4())

def verify_zkp_equation(g, u, h, v, d, C, e, p):
    try:
        g, u, h, v, d, C, e, p = map(convert_to_int, [g, u, h, v, d, C, e, p])
        left_side = (pow(g, u, p) * pow(h, v, p)) % p
        right_side = (d * pow(C, e, p)) % p
        return left_side == right_side
    except ValueError as ve:
        print(f"Invalid input: {ve}")
        return False
    except TypeError as te:
        print(f"Type error: {te}")
        return False
    
def compute_ksp(C, w, d, p):
    C, w, d, p = map(int, [C, w, d, p])
    ksp = (pow(C, w, p) * pow(d, w, p)) % p
    return ksp

def save_ksp_to_session_file(session_id, ksp):
    script_dir = os.path.dirname(os.path.abspath(__file__)) 
    session_keys_dir = os.path.join(script_dir, 'Session keys') 
    if not os.path.exists(session_keys_dir):
        os.makedirs(session_keys_dir)
    session_file_path = os.path.join(session_keys_dir, f"{session_id}_key") 
    with open(session_file_path, 'w') as file:
        file.write(str(ksp))

def load_ksp_from_session_file(session_id):
    script_dir = os.path.dirname(os.path.abspath(__file__)) 
    session_keys_dir = os.path.join(script_dir, 'Session keys') 
    session_file_path = os.path.join(session_keys_dir, f"{session_id}_key") 
    
    if os.path.exists(session_file_path):
        with open(session_file_path, 'r') as file:
            kuser = file.read().strip()  
        return kuser
    else:
        print(f"Session key file for session ID {session_id} does not exist.")
        return None
    
def update_d_and_e_values(session_id, new_d_value, new_e_value):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    csv_file = os.path.join(script_dir, 'auth_sessions.csv')
    
    if not os.path.exists(csv_file):
        raise FileNotFoundError("CSV file not found.")
    
    updated_rows = []
    
    with open(csv_file, mode='r', newline='') as file:
        reader = csv.reader(file)
        header = next(reader)
        session_id_index = header.index('session_id')
        d_index = header.index('d')
        e_index = header.index('e')
        
        updated_rows.append(header)
        
        for row in reader:
            if row[session_id_index] == session_id:
                row[d_index] = str(new_d_value)
                row[e_index] = str(new_e_value) 
            updated_rows.append(row)
    
    with open(csv_file, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerows(updated_rows)

def generate_timestamp():
    return datetime.now(timezone.utc).isoformat()

def generate_validate_challenge_e(challenge_e_non_checked, commitment_c, commitment_d, timestamp_nizkp):
    input_data = f"{commitment_c}{commitment_d}{timestamp_nizkp}".encode()
    challenge_hash = SHA256.new(input_data).hexdigest()
    
    return challenge_hash == challenge_e_non_checked
        
def convert_to_int(value):
    if value is None or value == "":
        return None 
    try:
        return int(value)  
    except ValueError:
        return int(value, 16)  

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

def delayed_delete(file_path): # problems on certain operating systems (windows) without delay
    time.sleep(5)
    try:
        os.remove(file_path)
    except Exception as e:
        print(f"Error deleting {file_path}: {str(e)}")