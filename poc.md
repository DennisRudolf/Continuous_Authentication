## Repository Structure

The repository is organized into three main directories, each representing a different entity in the system: **User (Client), Identity Provider, and Service Provider**. Each directory is self-contained, containing a main script, method implementations, and additional resources.

```bash
Git Repository
│ - client/
│   │ - user_interface.py
│   │ - client_methods.py
│   │ - images_user/
│   │ - Session key/ (temporary)
│   │ - symmetric_key.bin
│   │ - face_classifier_encrypted/
│
│ - IDP/
│   │ - idp_server.py
│   │ - idp_server_methods.py
│   │ - private_key.pem
│   │ - training_data/
│   │ - Uploads/ (temporary)
│
│ - Service Provider/
│   │ - sp_server.py
│   │ - sp_server_methods.py
│   │ - Session key/ (temporary)
│   │ - auth_session.csv (temporary)
```
## Setup Instructions

We have added a `requirements.txt` file to the repository, which contains all the necessary dependencies. Python version 3.12.x or 3.11.x needed. Follow the steps below to set up the project:

### 1. Clone the Repository
```sh
git clone <repository_url>
cd <repository_name>
```

### 2. Create a Virtual Environment
#### Mac/Linux:
```sh
python3 -m venv venv
source venv/bin/activate
```
#### Windows:
```sh
python -m venv venv
venv\Scripts\activate
```

### 3. Install Dependencies
```sh
pip install -r requirements.txt
```

### 4. Start the Application
Run the following command to start the `start_poc.py` file:
```sh
python start_poc.py
```
This will automatically start the Client, IDP Server, and SP Server.

### Notice: Stopping Processes Using Specific Ports (Linux/Mac)

If you encounter issues where certain ports (5678 or 5679) are already in use, you can follow these steps to identify and stop the processes occupying those ports. This may be necessary after restarting the server.

1. **Find the Process Using the Port**  
   Run the following command in the terminal to identify the processes occupying the ports:
   ```bash
   lsof -i :5679
   lsof -i :5678

2. **Stop the Process**
    Once you have the PID, you can stop the process by running the following command:
    ```bash
    kill <PID>

### 5. Register for an Account
1. Click on "No Account? Register Now!".
2. Fill in all the required information (password guidelines can be found by clicking the information icon). Then, drag and drop images from the "Training Images" folder.
3. Press "Submit" button.
4. Wait for the model to be trained. You'll receive a notification confirming successful registration once it's complete.
5. Close the registration window.

### 6. Start a Session
1. Choose either the interactive or non-interactive version, enter your password, and click "Start Session".
2. Enjoy seamless and continuous authentication! (Check terminal output)

### Notice: Private Key for SP
    The private key in the SP folder is only used to derive the public key. 
    Normally, the SP would access the public key database, but for the PoC, we have addressed this differently.