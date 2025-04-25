import os
import re
import tkinter as tk
from tkinter import messagebox
from tkinterdnd2 import TkinterDnD, DND_FILES 
import requests
from client_methods import commit_pedersen, extract_idt_token, extract_meta_data, derive_secrets, decrypt_classifier, decrypt_symmetric_key_with_S3, get_random_image_path_of_user, create_bid, compute_zkp_values, compute_kuser, save_kuser_to_session_file, encrypt_data_ecb, decrypt_data_ecb, load_kuser_from_session_file
import json
from datetime import datetime
from SVM_user import predict_label
from Crypto.Hash import SHA256

class Tooltip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tooltip_window = None

        self.widget.bind("<Enter>", self.show_tooltip)
        self.widget.bind("<Leave>", self.hide_tooltip)

    def show_tooltip(self, event=None):
        if self.tooltip_window is not None:
            return
        
        x = self.widget.winfo_rootx() + 20 
        y = self.widget.winfo_rooty() + 20
        self.tooltip_window = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)  
        tw.wm_geometry(f"+{x}+{y}")
        
        label = tk.Label(
            tw,
            text=self.text,
            justify="left",
            background="lightyellow",
            relief="solid",
            borderwidth=1,
            font=("Arial", 10, "normal")
        )
        label.pack(ipadx=5, ipady=2)

    def hide_tooltip(self, event=None):
        if self.tooltip_window:
            self.tooltip_window.destroy()
            self.tooltip_window = None

class MainWindow:
    def __init__(self, root):
        self.script_dir = os.path.dirname(os.path.abspath(__file__))
        self.root = root
        self.root.title("Continuous Authentication")
        self.root.geometry("800x500")

        font_settings = ("Arial", 14) 
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_columnconfigure(1, weight=1)
        
        for i in range(7): 
            self.root.grid_rowconfigure(i, weight=1)
        
        self.label = tk.Label(root, text="Continuous Authentication Client", font=font_settings)
        self.label.grid(row=0, column=0, columnspan=2, pady=20, sticky="nsew")
        
        self.sp_label = tk.Label(root, text="Select Service Provider:", font=font_settings)
        self.sp_label.grid(row=1, column=0, pady=5, padx=5, sticky="e")
        
        self.sp_options = ["Banking", "Employer", "University"]
        self.selected_sp = tk.StringVar(value=self.sp_options[1])
        
        self.sp_dropdown = tk.OptionMenu(root, self.selected_sp, *self.sp_options)
        self.sp_dropdown.config(font=font_settings)  
        self.sp_dropdown.grid(row=1, column=1, pady=5, padx=5, sticky="ew")

        self.sp_label_2 = tk.Label(root, text="Select interactive or non-interactive:", font=font_settings)
        self.sp_label_2.grid(row=2, column=0, pady=5, padx=5, sticky="e")
        
        self.sp_options_2 = ["Interactive", "Non-interactive"]
        self.selected_sp_2 = tk.StringVar(value=self.sp_options_2[0]) 
        
        self.sp_dropdown_2 = tk.OptionMenu(root, self.selected_sp_2, *self.sp_options_2)
        self.sp_dropdown_2.config(font=font_settings)
        self.sp_dropdown_2.grid(row=2, column=1, pady=5, padx=5, sticky="ew")

        self.label_funktion3 = tk.Label(root, text="Enter Password", font=font_settings)
        self.label_funktion3.grid(row=3, column=0, padx=5, pady=20, sticky="ew")
        
        self.entry_funktion3 = tk.Entry(root, show="*", font=font_settings)
        self.entry_funktion3.grid(row=3, column=1, padx=5, pady=20, sticky="ew")

        self.button_funktion3 = tk.Button(root, text="Start Session", font=font_settings, command=self.start_session)
        self.button_funktion3.grid(row=4, column=0, padx=5, pady=10, sticky="nsew")
        
        self.stop_button = tk.Button(root, text="Stop Session", font=font_settings, command=self.stop_continuous_auth, state=tk.DISABLED)
        self.stop_button.grid(row=4, column=1, padx=5, pady=10, sticky="nsew")

        self.timer_label = tk.Label(root, text="Session Time Remaining: 00:00:00", font=font_settings)
        self.timer_label.grid(row=5, column=0, columnspan=2, pady=10, sticky="nsew")

        self.button_funktion1 = tk.Button(root, text="No Account? Register now!", font=font_settings, command=self.register_new_user)
        self.button_funktion1.grid(row=6, column=0, padx=5, pady=20, sticky="ew")
        
        self.button_funktion2 = tk.Button(root, text="Reset your Account", font=font_settings, command=self.reset_account)
        self.button_funktion2.grid(row=6, column=1, padx=5, pady=20, sticky="ew")

        self.quit_button = tk.Button(root, text="Quit", font=font_settings, command=self.root.quit)
        self.quit_button.grid(row=7, column=0, columnspan=2, padx=5, pady=20, sticky="nsew") 

        # all Code above for the Tkinter main window

        self.stop_continuous_auth_flag = False 
        self.stop_timer_flag = False

    def start_session(self):
        self.session_start_password = self.entry_funktion3.get()
        selected_authentication_version = self.selected_sp_2.get() # get interactive or non-interactive information
        salt, idt_token = self.load_authentication_data() # extracts the data from json file
        self.stop_button.config(state=tk.NORMAL)
        if salt and idt_token:
            commitment_c, meta_data, message_singed = extract_idt_token(idt_token) # extracts the single components of data
            p, q, g, h, time_stamp = extract_meta_data(meta_data) # extracts the single components of data
            commitment_d, y, s = commit_pedersen(p, q, g, h) # Pedersen commitment d
        
        try:
            data_step1 = {
                'commitment': commitment_d,
                'idt_token': idt_token,
            }
            response_step1 = requests.post('http://127.0.0.1:5679/start_auth', json=data_step1) # sends data to SP
            if selected_authentication_version == "Interactive": # depending on version chosen in the front end the interactive or non-interactive functions are used
                self.interactive_authentication(response_step1, p,q,g,h,salt,y,s)
            elif selected_authentication_version == "Non-interactive":
                self.non_interactive_authentication(response_step1, p,q,g,h,salt,y,s, commitment_c)
            else:
                messagebox.showerror("Error", f"Chose either interactive or non-interactive version")

        except ValueError as ve:
                    messagebox.showerror("Error", f"Error, while computing response {str(ve)}")

    def interactive_authentication(self, response_step1, p, q, g, h, salt, y, s):
        if response_step1.status_code == 200:
                try:
                    response_json = response_step1.json()
                    session_id = response_json.get('session_id', None)
                    challenge_e = response_json.get('challenge', None)
                    a = response_json.get('a', None)
                    b = response_json.get('b', None)
                    session_timer = response_json.get("session_timer", None) # extracting JSON data from SP
                    S1, S2, S3 = derive_secrets(self.session_start_password, salt) # derive secrets from password
                    key = decrypt_symmetric_key_with_S3(S3)
                    decrypt_classifier(key=key) # decrypt the classifier with the symmetric key

                    if key is not False:
                        self.update_timer(session_timer)
                        image_path = get_random_image_path_of_user()
                        predicted_label = predict_label(image_path) # predicts the label from the image chosen above
                        if predicted_label is None:
                            messagebox.showerror("Error", "Initial authentication failed")  
                        BID = create_bid(predicted_label, S1)
                        u, v = compute_zkp_values(y, s, challenge_e, BID, S2, p)  # computes the ZKP values on the user sides and returns int
                        try:
                            data_step2 = {
                                'session_id': session_id,
                                'u': u,
                                'v': v,
                            }
                            response_step2 = requests.post('http://127.0.0.1:5679/start_auth_2', json=data_step2) # send data to SP

                            if response_step2.status_code == 200:
                                kuser = compute_kuser(a, BID, y, b, S2, s, p) # computes the session key and stores it 
                                save_kuser_to_session_file(session_id, kuser)
                                self.start_continuous_auth(session_id, p, q, g, h, S1, S2)  # Start continuous auth with ZKP
                            else:
                                messagebox.showerror("Error", "Initial authentication failed")
                        
                        except ValueError as ve:
                            messagebox.showerror("Error", f"Error parsing the response: {str(ve)}")
                    
                except ValueError as ve:
                    messagebox.showerror("Error", f"Error parsing the response: {str(ve)}")

    def non_interactive_authentication(self, response_step1, p, q, g, h, salt, y, s, commitment_c):
        if response_step1.status_code == 200:
                try:
                    response_json = response_step1.json()
                    session_id = response_json.get('session_id', None)
                    challenge_e = response_json.get('challenge', None)
                    a = response_json.get('a', None)
                    b = response_json.get('b', None)
                    session_timer = response_json.get("session_timer", None)
                    #timestamp_nizkp = response_json.get("timestamp_nizkp", None)
                    S1, S2, S3 = derive_secrets(self.session_start_password, salt)
                    key = decrypt_symmetric_key_with_S3(S3)
                    decrypt_classifier(key=key)

                    if key is not False:
                        self.update_timer(session_timer)
                        image_path = get_random_image_path_of_user()
                        predicted_label = predict_label(image_path) # similar to the version above
                        if predicted_label is None:
                            messagebox.showerror("Error", "Initial authentication failed") 
                        BID = create_bid(predicted_label, S1) # BID is generated
                        u, v = compute_zkp_values(y, s, challenge_e, BID, S2, p)  # returns int
                        try:
                            data_step2 = {
                                'session_id': session_id,
                                'u': u,
                                'v': v,
                            }
                            response_step2 = requests.post('http://127.0.0.1:5679/start_auth_2', json=data_step2)

                            if response_step2.status_code == 200:
                                kuser = compute_kuser(a, BID, y, b, S2, s, p)
                                save_kuser_to_session_file(session_id, kuser)
                                self.start_continuous_auth_nizkp(session_id, p, q, g, h, S1, S2, commitment_c, challenge_e)  # Start continuous auth with NIZKP
                            else:
                                messagebox.showerror("Error", "Initial authentication failed")
                        
                        except ValueError as ve:
                            messagebox.showerror("Error", f"Error parsing the response: {str(ve)}")
                    
                except ValueError as ve:
                    messagebox.showerror("Error", f"Error parsing the response: {str(ve)}")

    def start_continuous_auth(self, session_id, p, q, g, h, S1, S2):  # from here on the authentication loop starts, in this case for the interactive version
        self.stop_continuous_auth_flag = False 
        session_key = load_kuser_from_session_file(session_id) # loads session key for encryption
        def auth_loop():
            if self.stop_continuous_auth_flag: # if the uses stops the session, the decrypted classifier and session keys are deleted
                file_path = os.path.join(os.path.dirname(__file__), "face_classifier_decrypted.pkl")
                os.remove(file_path)
                session_key_folder = os.path.join(os.path.dirname(__file__), "Session key")
                for filename in os.listdir(session_key_folder):
                    file_path = os.path.join(session_key_folder, filename)
                    os.remove(file_path)
                print("Continuous authentication stopped by user.")
                self.stop_button.config(state=tk.DISABLED) 
                return 

            try:
                commitment_d, y, s = commit_pedersen(p, q, g, h)
                encrypted_values_1 = encrypt_data_ecb(session_key, commitment_d) # encrypts data before sending it
                encrypted_commitment_d = encrypted_values_1[0] 
                data_continuous = {
                    'session_id': session_id,
                    'commitment_d': encrypted_commitment_d
                }

                response_continuous = requests.post('http://127.0.0.1:5679/count_authZKP_1', json=data_continuous)
                
                if response_continuous.status_code == 200:
                    response_continuous_json = response_continuous.json()
                    encrypted_challenge_e = response_continuous_json.get('e', None)
                    encrypted_value = decrypt_data_ecb(session_key, encrypted_challenge_e) # decrypts data with session key
                    challenge_e = int(encrypted_value[0])

                    image_path = get_random_image_path_of_user()
                    predicted_label = predict_label(image_path)
                    if predicted_label is None:
                        messagebox.showerror("Error", "Authentication failed") 
                    BID = create_bid(predicted_label, S1)
                    u, v = compute_zkp_values(y, s, challenge_e, BID, S2, p)
                    encrypted_values_2 = encrypt_data_ecb(session_key, u, v) # encrypts data before sending it to SP
        
                    encrypted_u = encrypted_values_2[0]
                    encrypted_v = encrypted_values_2[1]
                    data_continuous_step_2 = {
                        'session_id': session_id,
                        'u': encrypted_u,
                        'v': encrypted_v,
                    }
                    response_continuous_step2 = requests.post('http://127.0.0.1:5679/count_authZKP_2', json=data_continuous_step_2)
                    
                    if response_continuous_step2.status_code == 200:
                        print("ZKP successful")
                        self.root.after(2000, auth_loop)  # waits before the loop is iterated again
                    else:
                        print("ZKP failed")
                        messagebox.showerror("Error", "Continuous authentication step 2 failed")
                        self.stop_button.config(state=tk.DISABLED) 
                elif response_continuous.status_code == 400:
                    messagebox.showinfo("Time expired", "Time has expired, new session is needed.")
                else:
                    messagebox.showerror("Error", "Continuous authentication failed")
                    self.stop_button.config(state=tk.DISABLED)  

            except ValueError as ve:
                messagebox.showerror("Error", f"Error with response {str(ve)}")
                self.stop_button.config(state=tk.DISABLED)  
            
        auth_loop()  
        
    def start_continuous_auth_nizkp(self, session_id, p, q, g, h, S1, S2, commitment_c, challenge_e): # from here on the authentication loop starts, in this case for the non-interactive version
        self.stop_continuous_auth_flag = False 
        session_key = load_kuser_from_session_file(session_id)

        def auth_loop():
            nonlocal challenge_e
            if self.stop_continuous_auth_flag: # if the uses stops the session, the decrypted classifier and session keys are deleted
                file_path = os.path.join(os.path.dirname(__file__), "face_classifier_decrypted.pkl")
                os.remove(file_path)
                session_key_folder = os.path.join(os.path.dirname(__file__), "Session key")
                for filename in os.listdir(session_key_folder):
                    file_path = os.path.join(session_key_folder, filename)
                    os.remove(file_path)
                print("Continuous authentication stopped by user.")
                self.stop_button.config(state=tk.DISABLED) 
                return 

            try:
                commitment_d, y, s = commit_pedersen(p, q, g, h)
                challenge_e_nizkp = self.generate_challenge_nizkp(commitment_c, commitment_d, challenge_e) 
                challenge_e += 1 # increments the challenge (here used as nonce as explained in the thesis) for the next iteration
                image_path = get_random_image_path_of_user()
                predicted_label = predict_label(image_path)
                if predicted_label is None:
                    messagebox.showerror("Error", "Authentication failed") 
                BID = create_bid(predicted_label, S1)
                u, v = compute_zkp_values(y, s, challenge_e_nizkp, BID, S2, p)
                encrypted_values = encrypt_data_ecb(session_key, u, v, challenge_e_nizkp, commitment_d)

                encrypted_u = encrypted_values[0]
                encrypted_v = encrypted_values[1]
                encrypted_challenge_e_nizkp = encrypted_values[2]
                encrypted_commitment_d = encrypted_values[3]
                data_continuous_nizkp = {
                    'session_id': session_id,
                    'u': encrypted_u,
                    'v': encrypted_v,
                    'challenge_e_nizkp': encrypted_challenge_e_nizkp,
                    'commitment_d': encrypted_commitment_d
                }
                
                response_continuous_nizkp = requests.post('http://127.0.0.1:5679/count_authNIZKP', json=data_continuous_nizkp)
                    
                if response_continuous_nizkp.status_code == 200:
                    print("NIZKP successful")
                    self.root.after(2000, auth_loop)  
                else:
                    print("NIZKP failed")
                    messagebox.showerror("Error", "Continuous authentication step 2 failed")
                    self.stop_button.config(state=tk.DISABLED)  

            except ValueError as ve:
                messagebox.showerror("Error", f"Error with response {str(ve)}")
                self.stop_button.config(state=tk.DISABLED) 

        auth_loop()  

    def generate_challenge_nizkp(self, commitment_c, commitment_d, challenge_e): # generates the challenge according to the scheme explained in the thesis
        input_data = f"{commitment_c}{commitment_d}{challenge_e}".encode()
        
        challenge_hash = SHA256.new(input_data).hexdigest()

        return challenge_hash

    def load_authentication_data(self):
        file_path = os.path.join(self.script_dir, "authentication_data.json")
        if os.path.exists(file_path):
            with open(file_path, "r") as file:
                data = json.load(file)
            
            salt = data.get("salt")
            idt_token = data.get("idt_token")
            return salt, idt_token
        else:
            print("No authentication data found.")
            return None, None
        
    def stop_continuous_auth(self):
        self.stop_continuous_auth_flag = True
        self.stop_timer_flag = True 

    def register_new_user(self): # setup the registration window
        self.registration_window = tk.Toplevel(self.root)
        self.registration_window.title("Registration")
        self.registration_window.geometry("1200x600")

        self.registration_window.grid_columnconfigure(0, weight=1)
        self.registration_window.grid_columnconfigure(1, weight=1)

        font_settings = ("Arial", 14) 

        self.name_label = tk.Label(self.registration_window, text="Enter your name:", font=font_settings)
        self.name_label.grid(row=0, column=0, pady=10, padx=10, sticky="w")
         
        self.name_entry = tk.Entry(self.registration_window, font=font_settings)
        self.name_entry.grid(row=0, column=1, pady=10, padx=10, sticky="ew")

        self.socnumber_label = tk.Label(self.registration_window, text="Enter Social Security number:", font=font_settings)
        self.socnumber_label.grid(row=0, column=2, pady=10, padx=10, sticky="w")

        self.socnumber_entry = tk.Entry(self.registration_window, font=font_settings)
        self.socnumber_entry.grid(row=0, column=3, pady=10, padx=10, sticky="ew")

        self.password_label = tk.Label(self.registration_window, text="Enter password:", font=font_settings)
        self.password_label.grid(row=1, column=0, pady=10, padx=10, sticky="w")

        self.password_entry = tk.Entry(self.registration_window, show="*", font=font_settings)
        self.password_entry.grid(row=1, column=1, pady=10, padx=10, sticky="ew")

        self.password_repeat_label = tk.Label(self.registration_window, text="Repeat password:", font=font_settings)
        self.password_repeat_label.grid(row=1, column=2, pady=10, padx=10, sticky="w")

        self.password_repeat_entry = tk.Entry(self.registration_window, show="*", font=font_settings)
        self.password_repeat_entry.grid(row=1, column=3, pady=10, padx=10, sticky="ew")

        self.password_info_label = tk.Label(self.registration_window, text="ℹ️", font=("Arial", 14), cursor="hand2")
        self.password_info_label.grid(row=1, column=4, padx=5, pady=10) 
        Tooltip(self.password_info_label, "Password must contain at least 8 characters,\n1 uppercase letter, 1 lowercase letter,\n1 number and 1 special character.")

        self.submit_button = tk.Button(self.registration_window, text="Submit", font=font_settings, command=self.submit_socnumber_password_images)
        self.submit_button.grid(row=2, column=0, columnspan=4, pady=10, sticky="ew")

        self.dnd_label = tk.Label(self.registration_window, text="Drag and drop at least 10 images", font=font_settings)
        self.dnd_label.grid(row=3, column=0, columnspan=4, pady=10, sticky="nsew")

        self.dnd_frame = tk.Frame(self.registration_window, bg="lightgrey", width=400, height=150)
        self.dnd_frame.grid(row=4, column=0, columnspan=4, pady=10, sticky="nsew")
        self.dnd_frame.pack_propagate(False)

        self.dnd_message = tk.Label(self.dnd_frame, text="Drop files here", bg="lightgrey", font=font_settings)
        self.dnd_message.pack(expand=True)

        self.registration_window.drop_target_register(DND_FILES)
        self.registration_window.dnd_bind('<<Drop>>', self.handle_drop)

        self.file_list = tk.Listbox(self.registration_window, height=6, font=font_settings)
        self.file_list.grid(row=5, column=0, columnspan=4, pady=10, sticky="nsew")


    def reset_account(self):
        pass
    
    def submit_socnumber_password_images(self):
        socnumber = self.socnumber_entry.get()
        password = self.password_entry.get()
        name = self.name_entry.get()
        password_repeat = self.password_repeat_entry.get()
        files = [self.file_list.get(idx) for idx in range(self.file_list.size())]
        min_images = self.check_images(files) # gets all the information from the GUI

        if password and socnumber and name and password == password_repeat and len(password) >= 8 \
                    and re.search(r'[A-Z]', password) \
                    and re.search(r'[a-z]', password) \
                    and re.search(r'[0-9]', password) \
                    and re.search(r'[!@#$%^&*(),.?":{}|<>]', password) \
                    and min_images: # validates the input 
            try:
                data = {
                    'name': name,
                    'socnumber': socnumber,
                    'password': password
                }
                file_payload = [('file', (os.path.basename(file), open(file, 'rb'))) for file in files]

                response = requests.post('http://127.0.0.1:5678/upload', data=data, files=file_payload) # sends data to IDP server

                if response.status_code == 200:
                    server_message = response.json().get('message', 'Success')
                    salt = response.json().get('salt', None)
                    idt_token = response.json().get('idt_token', None)
                    file_path = os.path.join(self.script_dir, "authentication_data.json")
                    data_to_save = {
                        "salt": salt,
                        "idt_token": idt_token
                    }
                    with open(file_path, "w") as file: # saves the data for the authentication later
                        json.dump(data_to_save, file)
                    # if salt and idt were successfully transferred, download all other data
                    if salt and idt_token:
                        self.download_classifier()
                        self.download_symmetric_key()

                else:
                    messagebox.showerror("Error", f"Failed to send data: {response.text}")

            except Exception as e:
                messagebox.showerror("Error", f"An error occurred while sending data: {str(e)}")
        else:
            messagebox.showwarning("Warning", "Password does not fulfill requirements or not enough images.")

    def download_classifier(self): # downloads and saves the classifier from the IDP
        try:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            file_path = os.path.join(base_dir, "face_classifier_encrypted.pkl")
            response = requests.get("http://127.0.0.1:5678/download_classifier", stream=True)
            if response.status_code == 200:
                with open(file_path, 'wb') as file:
                    for chunk in response.iter_content(chunk_size=8192):
                        file.write(chunk)
            else:
                messagebox.showerror("Error", "Failed to download the classifier file.")

        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")

    def download_symmetric_key(self): # downloads and saves the symmetric key from the IDP
        try:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            file_path = os.path.join(base_dir, "symmetric_key.bin")
            response = requests.get("http://127.0.0.1:5678/download_symmetric_key", stream=True)

            if response.status_code == 200:
                with open(file_path, 'wb') as file:
                    for chunk in response.iter_content(chunk_size=8192):
                        file.write(chunk)
                messagebox.showinfo("Success", "Registration successful")
            else:
                messagebox.showerror("Error", "Failed to download the symmetric key.")

        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
    
    def check_images(self, files): # checks if there are atleast 10 images and the extensions
        valid_extensions = {".jpg", ".jpeg", ".png"}        
        image_files = [file for file in files if os.path.splitext(file)[1].lower() in valid_extensions]
        
        if len(image_files) >= 10:
            return True
        else:
            return False   
    
    def handle_drop(self, event): # drag and drop function in registration window
        files = self.registration_window.tk.splitlist(event.data)
        for file in files:
            if os.path.exists(file):
                self.file_list.insert(tk.END, file)
            else:
                messagebox.showerror("Error", f"File not found: {file}")
            
    def update_timer(self, time_string): # upatdes the timer in GUI
        try:
            session_timer_datetime = datetime.strptime(time_string, "%Y-%m-%d %H:%M:%S")
            time_diff = session_timer_datetime - datetime.now()
            self.session_time_left = int(time_diff.total_seconds())
            
            def countdown():
                if self.session_time_left > 0 and not self.stop_timer_flag:
                    hours, remainder = divmod(self.session_time_left, 3600)
                    minutes, seconds = divmod(remainder, 60)
                    time_string = f"{hours:02}:{minutes:02}:{seconds:02}"
                    self.timer_label.config(text=f"Session Time Remaining: {time_string}")
                    self.session_time_left -= 1
                    self.root.after(1000, countdown)
                elif self.session_time_left <= 0:
                    self.timer_label.config(text="Session Time Remaining: 00:00:00")
            
            countdown()
        except ValueError as ve:
            messagebox.showerror("Error", f"Error parsing the time: {ve}")


def main(): # starts the GUI
    root = TkinterDnD.Tk()  
    app = MainWindow(root)
    root.mainloop()

if __name__ == "__main__":
    main()
