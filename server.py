import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import socket
import threading
import json
import base64
import datetime
from common import auth, crypto_utils
import db.db as db
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization

HOST = '127.0.0.1'
PORT = 65453
LOG_FILE = "server_logs.txt"


def log_event(event):
    timestamp = datetime.datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
    with open(LOG_FILE, "a") as f:
        f.write(f"{timestamp} {event}\n")


def handle_client(conn, addr):
    print(f"[+] Connection from {addr}")
    try:
     
        data = conn.recv(4096).decode()
        if not data:
            conn.close()
            return

        request = json.loads(data)
        if request.get("action") not in ["register", "login"]:
            conn.sendall("First action must be 'register' or 'login'.".encode())
            conn.close()
            return

        username = request.get("username")
        public_key = request.get("public_key")
        if not username or not public_key:
            conn.sendall("Missing username or public_key.".encode())
            conn.close()
            return

        if request.get("action") == "register":
            success, message = auth.register_user(username, public_key)
            log_event(f"[REGISTER] User: {username} - {'Success' if success else 'Failed'}")
        else:
            if not auth.authenticate_user(username):
                message = "User does not exist. Please register first."
                success = False
            else:
                message = "Login successful."
                success = True
                log_event(f"[LOGIN] User: {username} - Success")

        
        if username == "kaihan":
            auth.change_user_role(username, "admin")

        conn.sendall(message.encode())
        if not success:
            conn.close()
            return

        print(f"[+] User '{username}' connected.")

      
        parameters = dh.generate_parameters(generator=2, key_size=2048)
        server_private_key = parameters.generate_private_key()
        server_public_key = server_private_key.public_key()

        server_public_bytes = server_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        conn.sendall(server_public_bytes)
        print("[+] Sent server DH public key.")

        client_public_bytes = conn.recv(4096)
        client_public_key = serialization.load_pem_public_key(client_public_bytes)
        print("[+] Received client DH public key.")

        shared_key = server_private_key.exchange(client_public_key)
        symmetric_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data'
        ).derive(shared_key)
        print("[+] Derived symmetric key with DH.")

  
        while True:
            encrypted_data = conn.recv(4096)
            if not encrypted_data:
                break

            try:
                decrypted_message = crypto_utils.decrypt_message(symmetric_key, encrypted_data)
            except Exception as e:
                print(f"[!] Error decrypting message: {e}")
                log_event(f"[ERROR] Decryption failed for {username}: {e}")
                break

            print(f"[{username}] {decrypted_message}")

            try:
                request = json.loads(decrypted_message)
            except json.JSONDecodeError:
                response = "Invalid JSON data."
                conn.sendall(crypto_utils.encrypt_message(symmetric_key, response))
                continue

            action = request.get("action")
            if not auth.check_permission(username, action):
                response = "Permission denied."
                conn.sendall(crypto_utils.encrypt_message(symmetric_key, response))
                log_event(f"[DENIED] {username} tried: {action}")
                continue

          
            if action == "upload_file":
                filename = request.get("filename")
                file_data = request.get("file_data")
                signature = request.get("signature")
                if not filename or not file_data or not signature:
                    response = "Missing upload data."
                else:
                    file_data_bytes = base64.b64decode(file_data)
                    signature_bytes = base64.b64decode(signature)
               
                    encrypted_file = crypto_utils.encrypt_file(file_data_bytes, crypto_utils.SERVER_ENCRYPTION_KEY)
                    with open(f"server_storage/{filename}.enc", "wb") as f:
                        f.write(encrypted_file)
                    with open(f"server_storage/{filename}.sig", "wb") as f:
                        f.write(signature_bytes)
                    response = f"File '{filename}' uploaded and stored securely."
                    log_event(f"[UPLOAD] {username} uploaded '{filename}'.")

            elif action == "download_file":
                filename = request.get("filename")
                if not filename:
                    response = "Missing filename."
                else:
                    try:
                        with open(f"server_storage/{filename}.enc", "rb") as f:
                            encrypted_file = f.read()
                        decrypted_file = crypto_utils.decrypt_file(encrypted_file, crypto_utils.SERVER_ENCRYPTION_KEY)
                        with open(f"server_storage/{filename}.sig", "rb") as f:
                            signature = f.read()
                        response_data = {
                            "file_data": base64.b64encode(decrypted_file).decode(),
                            "signature": base64.b64encode(signature).decode()
                        }
                        response = json.dumps(response_data)
                        log_event(f"[DOWNLOAD] {username} downloaded '{filename}'.")
                    except FileNotFoundError:
                        response = f"File '{filename}' not found."

            elif action == "change_user_role":
                target_user = request.get("target_user")
                new_role = request.get("new_role")
                if not target_user or not new_role:
                    response = "Missing target_user or new_role."
                else:
                    success, msg = auth.change_user_role(target_user, new_role)
                    response = msg
                    log_event(f"[ROLE CHANGE] {username} changed '{target_user}' role to {new_role}.")

            elif action == "list_files":
                files = [f.replace(".enc", "") for f in os.listdir("server_storage") if f.endswith(".enc")]
                response = json.dumps({"files": files})
                log_event(f"[LIST FILES] {username} requested file list.")

            elif action == "delete_file":
                filename = request.get("filename")
                if not filename:
                    response = "Missing filename."
                else:
                    try:
                        os.remove(f"server_storage/{filename}.enc")
                        os.remove(f"server_storage/{filename}.sig")
                        response = f"File '{filename}' deleted successfully."
                        log_event(f"[DELETE] {username} deleted '{filename}'.")
                    except FileNotFoundError:
                        response = f"File '{filename}' not found."

            else:
                response = "Unknown action."
                log_event(f"[UNKNOWN ACTION] {username} sent: {action}")

            encrypted_response = crypto_utils.encrypt_message(symmetric_key, response)
            conn.sendall(encrypted_response)

    except Exception as e:
        print(f"[!] Error: {e}")
        log_event(f"[ERROR] General error with {addr}: {e}")
    finally:
        conn.close()
        print(f"[-] Disconnected {addr}")
        log_event(f"[-] {username} disconnected.")


def start_server():
    os.makedirs("server_storage", exist_ok=True)
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)
    print(f"[+] Server listening on {HOST}:{PORT}")
    log_event("[START] Server started.")
    while True:
        conn, addr = server_socket.accept()
        threading.Thread(target=handle_client, args=(conn, addr)).start()


if __name__ == "__main__":
    start_server()
