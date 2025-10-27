import socket
import json
import time
import uuid
import threading
import sys
from des_lib import (
    encrypt_message, 
    decrypt_message, 
    bits_to_custom_format, 
    custom_format_to_bits, 
    pad_key
)

# Global flags untuk kontrol server
server_running = True
shutdown_requested = False


def bidirectional_chat(client_socket, client_address, shared_key):
    global shutdown_requested
    
    print(f"\n{'='*70}")
    print(f"NEW SECURE SESSION with {client_address[0]}:{client_address[1]}")
    print(f"{'='*70}")
    print(f"Shared Key: '{shared_key}'")
    if shutdown_requested:
        print("(Server shutdown is scheduled after this session)")
    print(f"{'='*70}")
    
    try:
        message_count = 0
        
        while True:
            # === RECEIVE MESSAGE FROM CLIENT ===
            print(f"\n{'─'*70}")
            print("Waiting for client's message...")
            
            # Loop untuk receive data dengan timeout
            data = None
            while not data:
                try:
                    client_socket.settimeout(5.0)
                    data = client_socket.recv(8192).decode('utf-8')
                except socket.timeout:
                    # Timeout, terus tunggu tanpa print ulang
                    continue
                except Exception as e:
                    print(f"Connection error: {e}")
                    break
            
            if not data:
                print("Connection closed by client")
                break
            
            message_data = json.loads(data)
            
            if message_data['type'] == 'quit':
                print("\nClient has ended the session")
                break
            
            # Decrypt client's message
            client_ciphertext = message_data['ciphertext']
            client_ciphertext_bits = custom_format_to_bits(client_ciphertext)
            client_plaintext = decrypt_message(client_ciphertext_bits, shared_key)
            
            print(f"\nDecrypting client's message...")
            print(f"   Session ID: {message_data['session_id']}")
            print(f"   Message ID: {message_data['message_id']}")
            print(f"   Timestamp : {message_data['timestamp']}")
            print(f"   Received  : {client_ciphertext[:50]}..." if len(client_ciphertext) > 50 else f"   Received  : {client_ciphertext}")
            print(f"   Decrypted : '{client_plaintext}'")
            print(f"\n[CLIENT]: {client_plaintext}")
            
            # === SEND RESPONSE TO CLIENT ===
            print(f"\n{'─'*70}")
            print("Response options:")
            print("  - Press Enter to input Message")
            print("  - Type 'q' and enter to schedule end session after the client's quit")
            response_text = input("[YOU] Enter response: ")
            
            if response_text.lower() == 'quit':
                # Send quit signal
                quit_msg = json.dumps({'type': 'quit'})
                client_socket.send(quit_msg.encode('utf-8'))
                break
            
            # If empty (just Enter), send a default message
            if not response_text.strip():
                response_text = "Message received"
            
            message_count += 1
            
            # Create response with metadata
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            
            # Encrypt response
            response_bits = encrypt_message(response_text, shared_key)
            response_encoded = bits_to_custom_format(response_bits)
            
            print(f"\nEncrypting response...")
            print(f"   Plaintext : '{response_text}'")
            print(f"   Encrypted : {response_encoded[:50]}..." if len(response_encoded) > 50 else f"   Encrypted : {response_encoded}")
            
            # Send encrypted response
            response_data = {
                'type': 'message',
                'session_id': message_data['session_id'],
                'message_id': message_count,
                'timestamp': timestamp,
                'ciphertext': response_encoded
            }
            
            client_socket.send(json.dumps(response_data).encode('utf-8'))
            print(f"Encrypted response sent!")
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        client_socket.close()
        print(f"\n{'='*70}")
        print("Secure session ended")
        print(f"{'='*70}")


def start_server(host, port, shared_key):
    global server_running, shutdown_requested
    
    # Create server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.settimeout(1.0)  # Set timeout agar bisa cek server_running flag
    
    def shutdown_listener():
        """Thread untuk mendengarkan input 'q' untuk shutdown server"""
        global server_running, shutdown_requested
        while server_running:
            try:
                user_input = input()
                if user_input.lower() in ['q', 'quit', 'exit']:
                    print("\n>> Shutdown scheduled. Server will stop after current session ends.")
                    shutdown_requested = True
                    server_running = False
                    break
            except:
                break
    
    try:
        server_socket.bind((host, port))
        server_socket.listen(1)
        
        print("="*70)
        print("DES SECURE COMMUNICATION - SERVER (Device 2)")
        print("="*70)
        print(f"Server listening on {host}:{port}")
        print(f"Shared Key: '{shared_key}'")
        print("="*70)
        print(">> Type 'q' and press Enter to schedule shutdown")
        print("="*70)
        print("Waiting for client connection...")
        print("="*70)
        
        # Start shutdown listener thread
        shutdown_thread = threading.Thread(target=shutdown_listener, daemon=True)
        shutdown_thread.start()
        
        while server_running:
            try:
                # Accept client connection
                client_socket, client_address = server_socket.accept()
                print(f"\nClient connected from {client_address[0]}:{client_address[1]}")
                
                # Start bidirectional chat
                bidirectional_chat(client_socket, client_address, shared_key)
                
                # Check if shutdown was requested
                if shutdown_requested:
                    print("\n>> Shutdown requested. Closing server...")
                    break
                
                if server_running and not shutdown_requested:
                    print(f"\n{'='*70}")
                    print("Waiting for next client connection...")
                    print("(Type 'q' and Enter to shutdown)")
                    print(f"{'='*70}")
                    
            except socket.timeout:
                # Timeout terjadi, cek apakah server_running masih True
                continue
            except OSError:
                # Socket ditutup
                break
                
    except KeyboardInterrupt:
        print("\n\n>> Server interrupted by Ctrl+C...")
    finally:
        server_running = False
        server_socket.close()
        print("\n>> Server closed successfully")
        print("="*70)


if __name__ == "__main__":
    print("\n" + "="*70)
    print("DES SECURE BIDIRECTIONAL COMMUNICATION")
    print("="*70)
    
    # Configuration
    print("\nSERVER CONFIGURATION:")
    host_input = input("   Enter host (press Enter for 0.0.0.0): ").strip()
    HOST = host_input if host_input else '0.0.0.0'
    
    port_input = input("   Enter port (press Enter for 5555): ").strip()
    PORT = int(port_input) if port_input else 5555
    
    print("\nENCRYPTION KEY:")
    key_input = input("   Enter shared key (8 characters, will be padded if less): ").strip()
    SHARED_KEY = pad_key(key_input if key_input else "secret12")
    
    print(f"\nConfiguration complete!")
    print(f"   Host: {HOST}:{PORT}")
    print(f"   Key: '{SHARED_KEY}'")
    
    print("\nNOTE:")
    print("   - Make sure firewall allows connections on port", PORT)
    print("   - Client must use the same shared key!")
    print("   - For local testing: client uses 'localhost'")
    print("   - For network testing: client uses this server's IP address")
    
    input("\nPress Enter to start server...")
    
    start_server(HOST, PORT, SHARED_KEY)

