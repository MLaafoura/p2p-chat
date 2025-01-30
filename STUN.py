import socket
import threading
import random
import string


STUN_SERVER_IP = 'localhost'
STUN_SERVER_PORT = 12345

id_generator_lock = threading.Lock()
clients = {}

def generate_id(length=7):
    """Generate a random numeric ID"""
    characters = string.digits
    generated_id = ''.join(random.choices(characters, k=length))
    return int(generated_id)

def handle_client(server_socket, data, address):
    try:
        request = data.decode().split(' ')
        if len(request) == 0:
            server_socket.sendto("Invalid Request".encode(), address)
            return
        
        if request[0] == "REGISTER":
            # Check if listener port is provided
            listener_port = 0
            if len(request) > 1:
                try:
                    listener_port = int(request[1])
                except ValueError:
                    listener_port = 0
            register_client(server_socket, address, listener_port)
        
        elif request[0] == "REQUEST":
            if len(request) < 2:
                server_socket.sendto("Invalid REQUEST format".encode(), address)
                return
            request_client(server_socket, address, request[1])
        
        else:
            server_socket.sendto("Unknown Request".encode(), address)
    
    except Exception as e:
        server_socket.sendto(f"Error: {str(e)}".encode(), address)

def register_client(server_socket, address, listener_port=0):
    """Register a new client"""
    global id_generator
    
    id_generator_lock.acquire()
    try:
        client_id = generate_id()
    finally:
        id_generator_lock.release()
    
    ip, port = address
    
    # Store more detailed client information
    clients[client_id] = {
        'ip': ip,
        'port': port,
        'listener_port': listener_port
    }
    
    # Include listener port in response
    response = f"{client_id},{ip},{port},{listener_port}"
    server_socket.sendto(response.encode(), address)
    print(f"Registered client {client_id}: {ip}:{port} (Listener: {listener_port})")

def request_client(server_socket, address, client_id):
    """Request information about a specific client"""
    try:
        client_id = int(client_id)
        if client_id in clients:
            client_info = clients[client_id]
            ip = client_info['ip']
            port = client_info['port']
            listener_port = client_info.get('listener_port', 0)
            
            # Include listener port in response
            response = f"{ip},{port},{listener_port}"
            server_socket.sendto(response.encode(), address)
            print(f"Request for client {client_id}: {response}")
        else:
            server_socket.sendto(f"NOT_FOUND {client_id}".encode(), address)
    
    except ValueError:
        server_socket.sendto("Invalid client ID".encode(), address)
    except Exception as e:
        server_socket.sendto(f"Error: {str(e)}".encode(), address)

def main():
    #Main server loop
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_socket.bind((STUN_SERVER_IP, STUN_SERVER_PORT))
        print(f"STUN Server is listening on {STUN_SERVER_IP}:{STUN_SERVER_PORT}")
        
        while True:
            try:
                data, address = server_socket.recvfrom(4096)
                print(f"Received data from {address}: {data.decode()}")
                
                client_handler = threading.Thread(target=handle_client, args=(server_socket, data, address))
                client_handler.start()
            
            except Exception as e:
                print(f"Error in main loop: {str(e)}")
    except KeyboardInterrupt:
        print('\n Existing the program')
        exit()

if __name__ == "__main__":
    main()