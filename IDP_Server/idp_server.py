from flask import Flask, request, jsonify, send_file
import os
import shutil
import threading
import time
from idp_server_methods import (
    choose_training_persons, derive_secrets, create_bid, create_meta_data, sign_message, 
    concatenate_message, encrypt_classifier, initialize_pedersen, commit_pedersen, 
    create_time_stamp, delayed_delete
)
from train_model_new import FaceRecognitionModel

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
MAX_FILE_SIZE = 16 * 1024 * 1024  # 16MB


app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE

# Ensure the upload directory exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename): # checks the images
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg'}

@app.route('/upload', methods=['POST'])
def upload_file():
    try:
        # Extract form data
        socnumber = request.form.get('socnumber')
        password = request.form.get('password')
        name = request.form.get('name')

        if not socnumber or not password or not name:
            return jsonify({"message": "Social Security number, password, and name are required"}), 400

        # Validate file presence
        if 'file' not in request.files:
            return jsonify({"message": "No file part in request"}), 400

        uploaded_files = request.files.getlist('file')
        if not uploaded_files:
            return jsonify({"message": "No files uploaded"}), 400

        user_folder = os.path.join(UPLOAD_FOLDER, f"{socnumber}_Files")
        os.makedirs(user_folder, exist_ok=True)

        for file in uploaded_files:
            if file.filename == '':
                return jsonify({"message": "One or more files have no filename"}), 400
            if not allowed_file(file.filename):
                return jsonify({"message": "Invalid file type. Only PNG, JPG, and JPEG are allowed."}), 400
            
            file_path = os.path.join(user_folder, file.filename)
            file.save(file_path)

        # Training process
        names_training_users = choose_training_persons()
        model = FaceRecognitionModel()
        model.init_model(str(user_folder), names_training_users)

        target_user_label = model.get_target_user_label()
        model.train_classifier()
        model.save_model(os.path.join(BASE_DIR, "face_classifier.pkl")) # save the trained classifier

        S1, S2, S3, salt = derive_secrets(password) # derive the secrets from the user password
        BID = create_bid(target_user_label, S1)
        p, q, g, h = initialize_pedersen() # setup all values for the Pedersen commitment
        commitment = commit_pedersen(BID, S2, p, q, g, h)
        time_stamp = create_time_stamp() # time stamp for validity period

        message_signed = sign_message(commitment, g, h, p, q, time_stamp, name, socnumber) # sign the IDT data
        meta_data = create_meta_data(p, q, g, h, time_stamp, name, socnumber)
        idt_token = concatenate_message(commitment, meta_data, message_signed) # put together the IDT token as described in the thesis

        encrypt_classifier(S3) # key for encryption is generated in function, not encrypted with S3 as it may look like

        if os.path.exists(user_folder): # delete the images from IDP server after the training process
            shutil.rmtree(user_folder)
            
        return jsonify({"message": "Files successfully uploaded", "salt": salt, "idt_token": idt_token}), 200
    
    except Exception as e:
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500

@app.route('/download_classifier', methods=['GET'])
def download_classifier():
    try:
        file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "face_classifier_encrypted.pkl") # load and send the classifier to the user
        if os.path.exists(file_path):
            response = send_file(file_path, as_attachment=True)
            threading.Thread(target=delayed_delete, args=(file_path,)).start() # delete the classifier after it was send to the user
            return response
        return jsonify({"error": "File not found"}), 404
    except Exception as e:
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500

@app.route('/download_symmetric_key', methods=['GET'])
def download_symmetric_key():
    try:
        file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "symmetric_key.bin") # load the key and send it to the user
        if os.path.exists(file_path):
            response = send_file(file_path, as_attachment=True)
            threading.Thread(target=delayed_delete, args=(file_path,)).start() # delete the key after it was send to the user
            return response
        return jsonify({"error": "File not found"}), 404
    except Exception as e:
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5678) # start the Flask server on port 5678 in local mode
