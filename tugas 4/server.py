import socket
import json
import threading
import random
from des_lib import decrypt_message, custom_format_to_bits
from rsa_lib import generate_rsa_keypair, rsa_encrypt, rsa_decrypt
from signature_lib import verify_signature

server_running = True
clients = []
clients_lock = threading.Lock()
master_shared_key = None
server_private_key = None
server_public_key = None

def perform_key_exchange(client_socket, client_id):
    global master_shared_key, server_private_key, server_public_key
    
    try:
        if master_shared_key is None:
            chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
            master_shared_key = ''.join(random.choices(chars, k=8))
            print(f"\n[Server] Master key: '{master_shared_key}'")
        
        e, n = server_public_key
        pub_key_msg = {'type': 'rsa_public_key', 'e': e, 'n': n}
        client_socket.send(json.dumps(pub_key_msg).encode('utf-8'))
        
        client_socket.settimeout(30.0)
        data = client_socket.recv(8192).decode('utf-8')
        verify_msg = json.loads(data)
        
        if verify_msg['type'] != 'rsa_verify':
            raise Exception("Expected RSA verification")
        
        encrypted_data = verify_msg['encrypted_data']
        decrypted_bytes = rsa_decrypt(encrypted_data, server_private_key)
        verify_text = decrypted_bytes.decode('utf-8')
        
        if verify_text != 'CLIENT_HELLO':
            raise Exception("RSA verification failed")
        
        # Terima signature public key dari client
        data = client_socket.recv(8192).decode('utf-8')
        sig_key_msg = json.loads(data)
        
        if sig_key_msg['type'] != 'signature_public_key':
            raise Exception("Expected signature public key")
        
        client_sig_public_key = (sig_key_msg['e'], sig_key_msg['n'])
        
        key_msg = {'type': 'master_key', 'key': master_shared_key}
        client_socket.send(json.dumps(key_msg).encode('utf-8'))
        
        print(f"[Client {client_id}] Key: '{master_shared_key}'")
        print(f"[Client {client_id}] Signature public key received")
        return master_shared_key, client_sig_public_key
        
    except Exception as e:
        print(f"[Client {client_id}] Key exchange failed: {e}")
        return None


def handle_client(client_socket, client_address, client_id):
    print(f"\n[Client {client_id}] Connected: {client_address[0]}:{client_address[1]}")
    
    result = perform_key_exchange(client_socket, client_id)
    if not result:
        client_socket.close()
        return
    
    shared_key, client_sig_public_key = result
    
    with clients_lock:
        for i, (sock, cid, _) in enumerate(clients):
            if sock == client_socket:
                clients[i] = (sock, cid, shared_key, client_sig_public_key)
                break
        
        ready_clients = sum(1 for _, _, key, _ in clients if key is not None)
        
        if ready_clients >= 2:
            notify_msg = json.dumps({'type': 'ready', 'total_clients': ready_clients})
            for client_sock, cid, key, _ in clients:
                if key is not None:
                    try:
                        client_sock.send(notify_msg.encode('utf-8'))
                    except: pass
            print(f"\n[Server] Ready! ({ready_clients} clients)\n")
    
    try:
        while True:
            try:
                client_socket.settimeout(5.0)
                data = client_socket.recv(8192).decode('utf-8')
            except socket.timeout: continue
            except: break
            
            if not data:
                break
            
            try:
                message_data = json.loads(data)
            except:
                continue
            
            if message_data['type'] == 'quit':
                sender_name = message_data.get('sender_name', f'Client {client_id}')
                print(f"[{sender_name}] Quit")
                break
            
            try:
                sender_name = message_data.get('sender_name', f'Client {client_id}')
                ciphertext = message_data['ciphertext']
                signature = message_data.get('signature')
                
                ciphertext_bits = custom_format_to_bits(ciphertext)
                plaintext = decrypt_message(ciphertext_bits, shared_key)
                
                # Verify signature
                if signature is not None:
                    is_valid = verify_signature(plaintext, signature, client_sig_public_key)
                    sig_status = "✓ VALID" if is_valid else "✗ INVALID"
                    print(f"[{sender_name}] {plaintext} [{sig_status}]")
                else:
                    print(f"[{sender_name}] {plaintext} [NO SIGNATURE]")
            except Exception as e:
                print(f"[Error] Message processing failed: {e}")
            
            with clients_lock:
                for other_client, other_id, _, _ in clients:
                    if other_client != client_socket:
                        try:
                            other_client.send(data.encode('utf-8'))
                        except: pass
    
    except: pass
    
    finally:
        with clients_lock:
            clients[:] = [(sock, cid, key, sig_key) for sock, cid, key, sig_key in clients if sock != client_socket]
            remaining_clients = len(clients)
        
        client_socket.close()
        print(f"\n[Client {client_id}] Disconnected")
        
        if remaining_clients < 2 and remaining_clients > 0:
            wait_msg = json.dumps({'type': 'wait'})
            with clients_lock:
                for client_sock, cid, _, _ in clients:
                    try:
                        client_sock.send(wait_msg.encode('utf-8'))
                    except: pass


def start_server(host, port):
    global server_running, server_private_key, server_public_key
    
    print("\n" + "="*64)
    print("DES SECURE SERVER - RSA KEY DISTRIBUTION")
    print("="*64 + "\n")
    
    print("Generating RSA keypair...")
    server_public_key, server_private_key = generate_rsa_keypair(512)
    print("RSA Public Key generated\n")
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.settimeout(1.0)
    
    try:
        server_socket.bind((host, port))
        server_socket.listen(5)
        
        print("="*64)
        print(f"Listening: {host}:{port} | Encryption: DES with RSA")
        print("="*64 + "\n")
        
        client_counter = 0
        
        while server_running:
            try:
                client_socket, client_address = server_socket.accept()
                client_counter += 1
                
                client_thread = threading.Thread(
                    target=handle_client,
                    args=(client_socket, client_address, client_counter),
                    daemon=True
                )
                client_thread.start()
                
                with clients_lock:
                    clients.append((client_socket, client_counter, None, None))
                
                print(f"[Server] Total clients: {len(clients)}")
                
            except socket.timeout: continue
            except OSError: break
    
    except KeyboardInterrupt:
        print("\n[Server] Shutting down...")
    
    finally:
        server_running = False
        with clients_lock:
            for client_sock, _, _, _ in clients:
                try:
                    client_sock.close()
                except: pass
        server_socket.close()
        print("Server closed\n")


if __name__ == "__main__":
    print("\n" + "="*64)
    print("SERVER CONFIGURATION")
    print("="*64 + "\n")
    
    HOST = input("Host (default: 0.0.0.0): ").strip() or '0.0.0.0'
    PORT = int(input("Port (default: 5555): ").strip() or 5555)
    
    print(f"\n{'='*64}\nReady: {HOST}:{PORT}\n{'='*64}\n")
    input("Press Enter to start...")
    
    start_server(HOST, PORT)
