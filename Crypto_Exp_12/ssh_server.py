import paramiko
import socket
import threading
from pathlib import Path

# Generate host key if not exists
if not Path("ssh_host_key").exists():
    paramiko.RSAKey.generate(2048).write_private_key_file("ssh_host_key")

class SSHServer(paramiko.ServerInterface):
    def check_auth_password(self, username, password):
        print(f"Login attempt: {username}/{password}")
        return paramiko.AUTH_SUCCESSFUL  # Accept all for demo

def handle_connection(client_sock):
    transport = paramiko.Transport(client_sock)
    transport.add_server_key(paramiko.RSAKey(filename="ssh_host_key"))
    transport.start_server(server=SSHServer())

    channel = transport.accept(20)
    if channel:
        channel.send("Welcome to SSH Server! Type 'exit' to quit.\n")
        try:
            while True:
                data = channel.recv(1024).decode().strip()
                if not data or data.lower() == 'exit':
                    break
                print(f"Received: {data}")
                channel.send(f"Echo: {data}\n".encode())
        finally:
            channel.close()

def start_server(port=2222):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('localhost', port))
    sock.listen(5)
    print(f"SSH server running on port {port}")
    while True:
        client_sock, _ = sock.accept()
        threading.Thread(target=handle_connection, args=(client_sock,)).start()

if __name__ == "__main__":
    start_server()