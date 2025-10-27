import socket
import json
import time
import uuid
from des_lib import (
    encrypt_message, 
    decrypt_message, 
    bits_to_custom_format, 
    custom_format_to_bits, 
    pad_key
)


def bidirectional_chat(host, port, shared_key):
    print("="*70)
    print("DES SECURE COMMUNICATION - CLIENT (Device 1)")
    print("="*70)
    print(f"Shared Key: '{shared_key}'")
    print("="*70)
    
    try:
        # Connect to server
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((host, port))
        print(f"Connected to Server at {host}:{port}\n")
        
        # Generate session ID
        session_id = str(uuid.uuid4())[:8]
        
        # Chat loop
        message_count = 0
        while True:
            # === SEND MESSAGE TO SERVER ===
            print(f"\n{'─'*70}")
            plaintext = input("[YOU] Enter message to send (or 'quit' to exit): ")
            
            if plaintext.lower() == 'quit':
                # Send quit signal
                quit_msg = json.dumps({'type': 'quit'})
                client_socket.send(quit_msg.encode('utf-8'))
                break
            
            message_count += 1
            
            # Create message with metadata
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            
            # Encrypt message
            ciphertext_bits = encrypt_message(plaintext, shared_key)
            ciphertext_encoded = bits_to_custom_format(ciphertext_bits)
            
            print(f"\nEncrypting message...")
            print(f"   Plaintext : '{plaintext}'")
            print(f"   Encrypted : {ciphertext_encoded[:50]}..." if len(ciphertext_encoded) > 50 else f"   Encrypted : {ciphertext_encoded}")
            
            # Send encrypted message
            message_data = {
                'type': 'message',
                'session_id': session_id,
                'message_id': message_count,
                'timestamp': timestamp,
                'ciphertext': ciphertext_encoded
            }
            
            client_socket.send(json.dumps(message_data).encode('utf-8'))
            print(f"Encrypted message sent!")
            
            # === RECEIVE MESSAGE FROM SERVER ===
            print(f"\n{'─'*70}")
            print("Waiting for server's response...")
            
            response = client_socket.recv(8192).decode('utf-8')
            
            if not response:
                print("Connection closed by server")
                break
            
            response_data = json.loads(response)
            
            if response_data['type'] == 'quit':
                print("\nServer has ended the session")
                break
            
            # Decrypt server's message
            server_ciphertext = response_data['ciphertext']
            server_ciphertext_bits = custom_format_to_bits(server_ciphertext)
            server_plaintext = decrypt_message(server_ciphertext_bits, shared_key)
            
            print(f"\nDecrypting server's message...")
            print(f"   Received  : {server_ciphertext[:50]}..." if len(server_ciphertext) > 50 else f"   Received  : {server_ciphertext}")
            print(f"   Decrypted : '{server_plaintext}'")
            print(f"   Timestamp : {response_data['timestamp']}")
            print(f"\n[SERVER]: {server_plaintext}")
        
        client_socket.close()
        print(f"\n{'='*70}")
        print("Secure session ended")
        print(f"{'='*70}")
        
    except ConnectionRefusedError:
        print(f"\nError: Cannot connect to server at {host}:{port}")
        print("   Make sure the server is running!")
    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    print("\n" + "="*70)
    print("DES SECURE BIDIRECTIONAL COMMUNICATION")
    print("="*70)
    
    # Configuration
    print("\nSERVER CONFIGURATION:")
    host_input = input("   Enter server IP (press Enter for localhost): ").strip()
    HOST = host_input if host_input else 'localhost'
    
    port_input = input("   Enter server port (press Enter for 5555): ").strip()
    PORT = int(port_input) if port_input else 5555
    
    print("\nENCRYPTION KEY:")
    key_input = input("   Enter shared key (8 characters, will be padded if less): ").strip()
    SHARED_KEY = pad_key(key_input if key_input else "secret12")
    
    print(f"\nConfiguration complete!")
    print(f"   Server: {HOST}:{PORT}")
    print(f"   Key: '{SHARED_KEY}'")
    
    input("\nPress Enter to connect...")
    
    bidirectional_chat(HOST, PORT, SHARED_KEY)

