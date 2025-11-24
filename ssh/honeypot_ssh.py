#!/usr/bin/env python3
import socket
import threading
import json
import logging
import time
import os
from paramiko import ServerInterface, Transport, RSAKey, AUTH_SUCCESSFUL, AUTH_FAILED, OPEN_SUCCEEDED, OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

# --- CONFIGURATION ---
LOG_DIR = os.path.join(os.path.dirname(__file__), '..', 'logs')
if not os.path.exists(LOG_DIR):
    try:
        os.makedirs(LOG_DIR)
    except OSError:
        pass

LOGFILE = os.path.join(LOG_DIR, 'ssh.json')
logging.basicConfig(filename=LOGFILE, level=logging.INFO, format='%(message)s')

# Génération d'une clé hôte
HOST_KEY = RSAKey.generate(2048)

# Identifiants acceptés
VALID_USERS = {
    "admin": "password123",
    "root": "toor"
}

class FakeSSHServer(ServerInterface):
    def __init__(self, client_addr):
        self.client_addr = client_addr
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return OPEN_SUCCEEDED
        return OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        # Log de la tentative
        logging.info(json.dumps({
            "honeypot": "ssh",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "src_ip": self.client_addr[0],
            "src_port": self.client_addr[1],
            "username": username,
            "password": password,
            "action": "auth_attempt"
        }))

        # Vérification des identifiants
        if username in VALID_USERS and VALID_USERS[username] == password:
            return AUTH_SUCCESSFUL
        return AUTH_FAILED

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

def handle_shell(chan, client_addr):
    """Simule un shell interactif basique mais lit les VRAIS fichiers"""
    # On récupère le vrai hostname pour plus de réalisme
    hostname = socket.gethostname()
    chan.send(f"\r\nWelcome to {hostname} (GNU/Linux)\r\n\r\n".encode())
    
    prompt = b"root@server:~# "
    chan.send(prompt)
    
    command_buffer = ""

    while True:
        try:
            recv = chan.recv(1024)
            if not recv:
                break
            
            recv_char = recv.decode('utf-8', errors='ignore')
            
            if '\r' in recv_char or '\n' in recv_char:
                chan.send(b"\r\n")
                cmd = command_buffer.strip()
                
                if cmd:
                    # LOG de la commande exécutée
                    logging.info(json.dumps({
                        "honeypot": "ssh",
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "src_ip": client_addr[0],
                        "command": cmd,
                        "action": "command_execution"
                    }))
                    
                    # Réponses fausses pour les commandes système
                    response = b""
                    if cmd == "ls":
                        response = b"Desktop  Documents  Downloads  Music  Pictures  Public  Templates  Videos\r\n"
                    elif cmd == "pwd":
                        response = b"/root\r\n"
                    elif cmd == "whoami":
                        response = b"root\r\n"
                    elif cmd == "id":
                        response = b"uid=0(root) gid=0(root) groups=0(root)\r\n"
                    
                    # --- GESTION DE CAT (VRAIE LECTURE) ---
                    elif cmd.startswith("cat "):
                        try:
                            filename = cmd.split(" ", 1)[1].strip()
                            
                            # DANGER: Lecture réelle du fichier système
                            if os.path.isfile(filename):
                                try:
                                    with open(filename, 'rb') as f:
                                        content = f.read()
                                        # Conversion auto si c'est du texte, sinon raw bytes
                                        response = content + b"\r\n"
                                except PermissionError:
                                    response = f"cat: {filename}: Permission denied (Real System Error)\r\n".encode()
                                except Exception as e:
                                    response = f"cat: error: {str(e)}\r\n".encode()
                            else:
                                response = f"cat: {filename}: No such file or directory\r\n".encode()
                                
                        except IndexError:
                            response = b"usage: cat [filename]\r\n"

                    elif cmd == "exit":
                        chan.close()
                        break
                    else:
                        response = f"bash: {cmd}: command not found\r\n".encode()
                    
                    chan.send(response)
                
                command_buffer = ""
                chan.send(prompt)
            
            elif recv_char == '\x7f': # Backspace
                if len(command_buffer) > 0:
                    command_buffer = command_buffer[:-1]
                    chan.send(b"\b \b")
            else:
                command_buffer += recv_char
                chan.send(recv)
                
        except Exception:
            break

def handle_client(client_socket, addr):
    t = Transport(client_socket)
    t.add_server_key(HOST_KEY)
    server = FakeSSHServer(addr)
    
    try:
        t.start_server(server=server)
        chan = t.accept(30)
        if chan is None:
            t.close()
            return
        server.event.wait(10)
        if not server.event.is_set():
            chan.close()
            t.close()
            return
        handle_shell(chan, addr)
    except Exception:
        pass
    finally:
        try:
            t.close()
        except:
            pass

def run(host='0.0.0.0', port=2222):
    print(f"[*] SSH Honeypot listening on {host}:{port}")
    print(f"[*] WARNING: Real file access is ENABLED via 'cat'")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(100)
    while True:
        try:
            client, addr = s.accept()
            threading.Thread(target=handle_client, args=(client, addr), daemon=True).start()
        except Exception as e:
            print(f"Error accepting connection: {e}")

if __name__ == "__main__":
    run()
