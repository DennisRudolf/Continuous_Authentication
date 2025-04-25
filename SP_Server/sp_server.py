from flask import Flask, request, jsonify, send_file
from pathlib import Path
import os
import shutil
from sp_server_methods import (
    extract_idt_token, verify_signature, is_timestamp_not_expired,
    generate_e_w, create_time_stamp, extract_meta_data,
    generate_a_b, generate_unique_session_id, save_auth_values, load_auth_values, verify_zkp_equation,
    compute_ksp, save_ksp_to_session_file, update_d_and_e_values, generate_timestamp, generate_validate_challenge_e, 
    encrypt_data_ecb, decrypt_data_ecb, load_ksp_from_session_file
)

# Constants
PORT = 5679
ERROR_MISSING_FIELDS = {"error": "Missing required fields"}
ERROR_SESSION_EXPIRED = {"error": "Session expired"}
SUCCESS_ZKP_VERIFIED = {"status": "success", "message": "Zero-knowledge proof verification successful"}
FAILURE_ZKP_VERIFIED = {"status": "failure", "message": "Verification failed"}

# Flask App
app = Flask(__name__)

def validate_json_fields(data, required_fields):
    missing_fields = [field for field in required_fields if field not in data]
    if missing_fields:
        return jsonify({"error": f"Missing fields: {', '.join(missing_fields)}"}), 400
    return None

@app.route('/start_auth', methods=['POST'])
def start_auth():
    try:
        data = request.json
        required_fields = ['commitment', 'idt_token']
        validation_response = validate_json_fields(data, required_fields)
        if validation_response:
            return validation_response

        commitment_d = data['commitment']
        idt_token = data['idt_token']

        commitment_c, meta_data, message_signed = extract_idt_token(idt_token)
        p, q, g, h, time_stamp, name, socnumber = extract_meta_data(meta_data) # extracts all the data from the IDT
        if not (verify_signature(commitment_c, g, h, p, q, time_stamp, message_signed, name, socnumber) and is_timestamp_not_expired(time_stamp)): # verify the signature over the IDT and if the timestamp is not expired
            return jsonify({"message": "Session couldn’t be started"}), 400

        session_id = generate_unique_session_id() # needed for identification in the implementation of the PoC to map a user to data
        session_timer = create_time_stamp(0.5) # timer that is later dispayed in the user GUI after which the session terminates
        e, w = generate_e_w(q) 
        a, b = generate_a_b(g, h, p, w) # challenge and values for the symmetric key are generated
        save_auth_values(session_id, p, q, g, h, commitment_d, commitment_c, e, w, session_timer) # saved to the database where they can be extracted ussing the session id
        response_data = {
            "session_id": session_id,
            "challenge": e,
            "a": a,
            "b": b,
            "session_timer": session_timer,
        }

        return jsonify(response_data), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/start_auth_2', methods=['POST'])
def start_auth_step2():
    try:
        data = request.json
        required_fields = ['session_id', 'u', 'v']
        validation_response = validate_json_fields(data, required_fields)
        if validation_response:
            return validation_response

        session_id = data['session_id']
        u, v = data['u'], data['v']
        p, _, g, h, commitment_d, commitment_c, e, w, *_ = load_auth_values(session_id)

        if verify_zkp_equation(g, u, h, v, commitment_d, commitment_c, e, p): # verify the validity of the ZKP
            ksp = compute_ksp(commitment_c, w, commitment_d, p)
            save_ksp_to_session_file(session_id, ksp) # compute the symmetric key for encryption in the continuous authentication loop
            return jsonify(SUCCESS_ZKP_VERIFIED), 200

        return jsonify(FAILURE_ZKP_VERIFIED), 400

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/count_authZKP_1', methods=['POST'])
def continuous_authentication():
    try:
        data = request.json
        required_fields = ['session_id', 'commitment_d']
        validation_response = validate_json_fields(data, required_fields)
        if validation_response:
            return validation_response

        session_id = data['session_id']
        session_key = load_ksp_from_session_file(session_id) # uses the session id to map the session key to the user
        encrypted_commitment_d = data['commitment_d']
        decrypted_values = decrypt_data_ecb(session_key, encrypted_commitment_d)
        commitment_d = decrypted_values[0] # decrypts the commitment with the symmetric key

        q, session_timer = load_auth_values(session_id, only_q=True, only_session_timer=True)
        e = generate_e_w(q, only_e=True) # generates a new e for the next challenge

        update_d_and_e_values(session_id, commitment_d, e) # updates these values in the database for later resuage
        encrypted_value = encrypt_data_ecb(session_key, e) # encryption version; delete if needed
        encrypted_e = encrypted_value[0]

        if is_timestamp_not_expired(session_timer):
            return jsonify({"e": encrypted_e}), 200

        return jsonify(ERROR_SESSION_EXPIRED), 400

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/count_authZKP_2', methods=['POST'])
def continuous_authentication_step_2():
    try:
        data = request.json
        required_fields = ['session_id', 'u', 'v']
        validation_response = validate_json_fields(data, required_fields)
        if validation_response:
            return validation_response

        session_id = data['session_id']
        session_key = load_ksp_from_session_file(session_id)
        encrypted_u, encrypted_v = data['u'], data['v']
        decrypted_values = decrypt_data_ecb(session_key, encrypted_u, encrypted_v)
        u = decrypted_values[0]
        v = decrypted_values[1] # decrypts the values
        p, _, g, h, commitment_d, commitment_c, e, *_ = load_auth_values(session_id) # loads values based on session id

        if verify_zkp_equation(g, u, h, v, commitment_d, commitment_c, e, p): # checks if the ZKP holds 
            return jsonify(SUCCESS_ZKP_VERIFIED), 200

        return jsonify(FAILURE_ZKP_VERIFIED), 400

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/count_authNIZKP', methods=['POST'])
def continuous_authentication_nizkp():
    try:
        data = request.json
        session_id = data.get('session_id')
        session_key = load_ksp_from_session_file(session_id)
        encrypted_u = data.get('u')
        encrypted_v = data.get('v')
        encrypted_commitment_d = data.get('commitment_d')
        encrypted_challenge_e_nizkp = data.get('challenge_e_nizkp')
        decrypted_values = decrypt_data_ecb(session_key, encrypted_u, encrypted_v, encrypted_commitment_d, encrypted_challenge_e_nizkp)
        u = decrypted_values[0]
        v = decrypted_values[1]
        commitment_d = decrypted_values[2]
        challenge_e_nizkp = decrypted_values[3] # decrypts all the data from the user
        p, _, g, h, _unused1, commitment_c, e, *_ = load_auth_values(session_id) # session timer not needed
        
        challenge_validity = generate_validate_challenge_e(challenge_e_nizkp, commitment_c, commitment_d, e) # checks if the challenge was generated correctly by the user before checking the ZKP
        e += 1 # increments the e for the next iteration of the protocol
        update_d_and_e_values(session_id, commitment_d, e) # update of d technically not needed here, but for e

        if challenge_validity:
            if not u or not v:
                return jsonify({"error": "Missing commitment or idt_token"}), 400
            
            result_zkp = verify_zkp_equation(g, u, h, v, commitment_d, commitment_c, challenge_e_nizkp, p) # checks the ZKP equation

            if result_zkp:
                return jsonify({"status": "success", "message": "Zero-knowledge proof verification successful"}), 200
            else:
                return jsonify({"status": "failure", "message": "Verification failed"}), 400
        else:
            return jsonify({"status": "failure", "message": "Challenge wasn`t constructed correctly"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500  
    
if __name__ == '__main__':
    app.run(debug=True, port=5679) # starts the Flask server on the local port 5679 (different to the IDP server)