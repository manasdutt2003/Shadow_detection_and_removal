import socket
import threading
import sys

def handle_client(conn, addr):
    try:
        print(f"Connection from {addr}")
        conn.sendall(b"Welcome to Telnet Server! Type 'exit' to quit.\n")
        
        while True:
            data = conn.recv(1024)
            if not data:
                break
            message = data.decode().strip()
            print(f"Received: {message}")
            
            if message.lower() == 'exit':
                break
                
            conn.sendall(f"Echo: {message}\n".encode())
                
    except ConnectionResetError:
        print(f"Client {addr} disconnected abruptly")
    except Exception as e:
        print(f"Error with {addr}: {e}")
    finally:
        conn.close()
        print(f"Connection with {addr} closed")

def start_server(port=2323):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(('0.0.0.0', port))
            s.listen()
            print(f"Telnet server started on port {port}")
            
            while True:
                conn, addr = s.accept()
                thread = threading.Thread(target=handle_client, args=(conn, addr))
                thread.start()
                print(f"Active connections: {threading.active_count() - 1}")
                
    except PermissionError:
        print(f"Error: Need admin rights to use port {port}")
    except Exception as e:
        print(f"Server error: {e}")

if __name__ == "__main__":
    start_server()