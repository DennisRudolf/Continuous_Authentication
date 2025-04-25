import subprocess
import os
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

FOLDERS = {
    "client": "Client",
    "idp": "IDP_Server",
    "sp": "SP_Server"
}

def start_process(folder, script, wait=False):
    script_path = os.path.join(BASE_DIR, FOLDERS[folder], script)
    if wait:
        subprocess.run([sys.executable, script_path], check=True)
    else:
        subprocess.Popen([sys.executable, script_path])

start_process("idp", "idp_server.py")
start_process("sp", "sp_server.py")

start_process("client", "user_interface.py", wait=True)


# both servers and the GUI is started in one terminal to execute registration and authentication without restarting the servers