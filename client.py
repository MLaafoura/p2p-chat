import socket
import threading
import datetime
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet


STUN_SERVER_IP = 'localhost'
STUN_SERVER_PORT = 12345

def generate_rsa_keys():
    """Generate RSA key pair"""
    private_key = rsa.generate_private_key(
        public_exponent=65537, 
        key_size=2048
    )
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_key, public_pem

def generate_aes_key():
    """Generate a symmetric AES key"""
    return Fernet.generate_key()

def encrypt_aes_key_with_rsa(aes_key, peer_public_key):
    """Encrypt AES key using peer's RSA public key"""
    encrypted_aes_key = peer_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_aes_key

def decrypt_aes_key_with_rsa(encrypted_aes_key, private_key):
    """Decrypt AES key using our RSA private key"""
    decrypted_aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_aes_key

def start_tcp_listener(my_public_pem, my_aes_key, private_key, bind_ip='0.0.0.0', bind_port=0):
    tcp_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp_listener.bind((bind_ip, bind_port))
    tcp_listener.listen(1)
    
    listener_port = tcp_listener.getsockname()[1]
    
    def listener_thread():
        try:
            print(f"TCP Listener waiting on port {listener_port}")
            client_socket, address = tcp_listener.accept()
            print(f"Accepted TCP connection from {address}")
            
            client_socket.sendall(my_public_pem)
            
            peer_public_key_pem = client_socket.recv(4096)
            peer_public_key = serialization.load_pem_public_key(peer_public_key_pem)
            
            encrypted_aes_key = encrypt_aes_key_with_rsa(my_aes_key, peer_public_key)
            client_socket.sendall(encrypted_aes_key)
            
            peer_encrypted_aes_key = client_socket.recv(4096)
            peer_aes_key = decrypt_aes_key_with_rsa(peer_encrypted_aes_key, private_key)
            
            client_socket.close()
            return peer_public_key, peer_aes_key
        
        except Exception as e:
            print(f"TCP Listener error: {e}")
            return None, None
    
    listener_thread_obj = threading.Thread(target=listener_thread)
    listener_thread_obj.daemon = True
    listener_thread_obj.start()
    
    return tcp_listener, listener_port

def temporary_tcp_key_exchange(client_ip, client_port, my_public_pem, my_aes_key, private_key):
    """
    Attempt to establish a TCP connection to exchange keys
    """
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_socket.settimeout(60)
    
    try:
        tcp_socket.connect((client_ip, int(client_port)))
        print(f"Connected to peer at {client_ip}:{client_port} for key exchange.")
        
        peer_public_key_pem = tcp_socket.recv(4096)
        peer_public_key = serialization.load_pem_public_key(peer_public_key_pem)
        
        tcp_socket.sendall(my_public_pem)
        
        peer_encrypted_aes_key = tcp_socket.recv(4096)
        peer_aes_key = decrypt_aes_key_with_rsa(peer_encrypted_aes_key, private_key)
        
        encrypted_aes_key = encrypt_aes_key_with_rsa(my_aes_key, peer_public_key)
        tcp_socket.sendall(encrypted_aes_key)
        
        return peer_public_key, peer_aes_key

    except socket.timeout:
        print(f"Connection to {client_ip}:{client_port} timed out.")
        return None, None
    except Exception as e:
        print(f"Error during TCP connection: {e}")
        return None, None
    finally:
        tcp_socket.close()

def encrypt_message(message, aes_key):
    """Encrypt message using Fernet (AES)"""
    fernet = Fernet(aes_key)
    encrypted_message = fernet.encrypt(message.encode())
    return encrypted_message

def decrypt_message(encrypted_message, aes_key):
    """Decrypt message using Fernet (AES)"""
    fernet = Fernet(aes_key)
    message = fernet.decrypt(encrypted_message)
    return message

def send_message(message, client_socket, client_ip, client_port, shared_aes_key=None):
    if not message:
        print('Message cannot be empty!!\n')
        return None
    
    try:
        if shared_aes_key:
            try:
                encrypted_message = encrypt_message(message, shared_aes_key)
                client_socket.sendto(encrypted_message, (client_ip, int(client_port)))
            except Exception as encrypt_error:
                print(f"Encryption error: {encrypt_error}")
                client_socket.sendto(message.encode(), (client_ip, int(client_port)))
        else:
            client_socket.sendto(message.encode(), (client_ip, int(client_port)))
        
        return message
    
    except Exception as e:
        print(f"Error sending message: {e}")
        return None

def listen(client_socket, shared_aes_key=None):
    """This function is now only used for debugging/console output"""
    while True:
        try:
            # Check if the socket is still valid
            if client_socket.fileno() == -1:
                print("Socket is closed. Exiting listener.")
                break

            message, address = client_socket.recvfrom(1024)

            if shared_aes_key:
                try:
                    decrypted_message = decrypt_message(message, shared_aes_key)
                    message = decrypted_message.decode()
                except Exception as decrypt_error:
                    print(f"Decryption failed: {decrypt_error}. Might be an unencrypted message.")
                    message = message.decode()
            
            print(f"\nReceived Message: {message} (Received at {datetime.datetime.now()})")
            
        except Exception as e:
            print(f"Error receiving message: {e}")
            break


def register_client(client_socket, listener_port):
        client_socket.sendto(f"REGISTER {listener_port}".encode(), (STUN_SERVER_IP, STUN_SERVER_PORT))
        response = client_socket.recv(1024).decode()
        
        my_id, my_ip, my_port, *rest = response.split(',')
        return my_id

def request_client(client_socket, client_id):
    client_socket.sendto(f"REQUEST {client_id}".encode(), (STUN_SERVER_IP, STUN_SERVER_PORT))
    response = client_socket.recv(1024).decode()
    if response.startswith("NOT_FOUND"):
            print(f"Client {client_id} does not exist")
            return
  
    client_ip, client_port, peer_listener_port = response.split(",")

    
    print(f"Connecting to Client ID: {client_id}")
    return client_ip, client_port, peer_listener_port


def keys_exchange(client_socket, client_ip, client_port, peer_listener_port, my_public_pem, my_aes_key, private_key, tcp_listener):
    try:
        peer_public_key, shared_aes_key = temporary_tcp_key_exchange(
            client_ip, peer_listener_port, my_public_pem, my_aes_key, private_key
        )
        
        if shared_aes_key is None:
            print('Failed to securely exchange keys.')
            return None, None
        client_handler = threading.Thread(
            target=listen, 
            args=(client_socket, shared_aes_key)
        )
        client_handler.daemon = True
        client_handler.start()
        
        return peer_public_key, shared_aes_key
        
    except KeyboardInterrupt:
        print('\nExiting the program')
        return None, None
    except Exception as e:
        print(f"Unexpected error in keys_exchange: {e}")
        return None, None

def main():
   pass
    
    


if __name__ == "__main__":
    main()