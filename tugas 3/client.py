import socket
import json
import time
import uuid
import threading
from des_lib import encrypt_message, decrypt_message, bits_to_custom_format, custom_format_to_bits
from rsa_lib import rsa_encrypt

running = True
can_send = False

def perform_key_exchange(client_socket):
    try:
        data = client_socket.recv(8192).decode('utf-8')
        pub_key_msg = json.loads(data)
        
        if pub_key_msg['type'] != 'rsa_public_key':
            raise Exception("Expected RSA public key")
        
        server_public_key = (pub_key_msg['e'], pub_key_msg['n'])
        
        verify_message = 'CLIENT_HELLO'.encode('utf-8')
        encrypted_verify = rsa_encrypt(verify_message, server_public_key)
        
        verify_msg = {'type': 'rsa_verify', 'encrypted_data': encrypted_verify}
        client_socket.send(json.dumps(verify_msg).encode('utf-8'))
        
        data = client_socket.recv(8192).decode('utf-8')
        key_msg = json.loads(data)
        
        if key_msg['type'] != 'master_key':
            raise Exception("Expected master key")
        
        master_key = key_msg['key']
        print(f"\nMaster key: '{master_key}'\n")
        return master_key
        
    except Exception as e:
        print(f"[Key Exchange] Failed: {e}")
        return None


def receive_messages(client_socket, shared_key, my_name):
    global running, can_send
    
    while running:
        try:
            client_socket.settimeout(1.0)
            data = client_socket.recv(8192).decode('utf-8')
            
            if not data:
                print("\n[System] Connection closed")
                running = False
                break
            
            try:
                message_data = json.loads(data)
            except: continue
            
            if message_data['type'] == 'wait':
                can_send = False
                print(f"\n{'='*64}\n[System] Waiting for another client...\n{'='*64}\n")
                continue
            
            if message_data['type'] == 'ready':
                can_send = True
                print(f"\n{'='*64}\n[System] Chat ready!\n{'='*64}\n")
                print(f"[{my_name}] Enter message: ", end='', flush=True)
                continue
            
            if message_data['type'] == 'quit':
                can_send = False
                sender_name = message_data.get('sender_name', 'Other client')
                print(f"\n[System] {sender_name} left\n")
                continue
            
            try:
                sender_name = message_data.get('sender_name', 'Unknown')
                ciphertext = message_data['ciphertext']
                ciphertext_bits = custom_format_to_bits(ciphertext)
                plaintext = decrypt_message(ciphertext_bits, shared_key)
                
                print(f"\n\n[Recieved] {ciphertext[:60]}...")
                print(f"[{sender_name}] {plaintext}\n")
                print(f"[{my_name}] Enter message: ", end='', flush=True)
            except Exception as e:
                print(f"\n[Error] Decrypt failed: {e}")
        
        except socket.timeout: continue
        except Exception as e:
            if running:
                print(f"\n[Error] Receive error: {e}")
            break


def bidirectional_chat(host, port, client_name):
    global running, can_send
    
    print(f"\n{'='*64}\nDES SECURE CLIENT\n{'='*64}")
    print(f"Name: {client_name} | Server: {host}:{port}\n{'='*64}\n")
    
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((host, port))
        
        shared_key = perform_key_exchange(client_socket)
        if not shared_key:
            client_socket.close()
            return
        
        print("Waiting for another client...\n")
        client_socket.settimeout(None)
        
        while True:
            try:
                data = client_socket.recv(8192).decode('utf-8')
                message_data = json.loads(data)
                
                if message_data['type'] == 'ready':
                    print("Ready! Type 'quit' to exit\n")
                    can_send = True
                    break
            except: return
        
        session_id = str(uuid.uuid4())[:8]
        
        receive_thread = threading.Thread(
            target=receive_messages,
            args=(client_socket, shared_key, client_name),
            daemon=True
        )
        receive_thread.start()
        
        message_count = 0
        
        while running:
            try:
                plaintext = input(f"[{client_name}] Enter message: ")
                
                if not running:
                    break
                
                if plaintext.lower() == 'quit':
                    quit_msg = {'type': 'quit', 'sender_name': client_name}
                    client_socket.send(json.dumps(quit_msg).encode('utf-8'))
                    running = False
                    break
                
                if not plaintext.strip():
                    continue
                
                if not can_send:
                    print("[System] Waiting for another client...")
                    continue
                
                message_count += 1
                ciphertext_bits = encrypt_message(plaintext, shared_key)
                ciphertext_encoded = bits_to_custom_format(ciphertext_bits)
                
                message_data = {
                    'type': 'message',
                    'sender_name': client_name,
                    'session_id': session_id,
                    'message_id': message_count,
                    'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
                    'ciphertext': ciphertext_encoded
                }
                
                client_socket.send(json.dumps(message_data).encode('utf-8'))
                
            except KeyboardInterrupt:
                running = False
                break
            except: break
        
        client_socket.close()
        print(f"\n{'='*64}\nConnection closed\n{'='*64}")
    
    except ConnectionRefusedError:
        print(f"\nError: Cannot connect to {host}:{port}")
    except: pass


if __name__ == "__main__":
    print(f"\n{'='*64}\nCLIENT CONFIGURATION\n{'='*64}\n")
    
    client_name = input("Your name: ").strip() or "Anonymous"
    HOST = input("Server IP (default: localhost): ").strip() or 'localhost'
    PORT = int(input("Server port (default: 5555): ").strip() or 5555)
    
    print(f"\n{'='*64}\nReady: {client_name} @ {HOST}:{PORT}\n{'='*64}\n")
    input("Press Enter to connect...")
    
    bidirectional_chat(HOST, PORT, client_name)

