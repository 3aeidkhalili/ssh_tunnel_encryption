import paramiko
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
import os
import zlib

# Display a banner
print("\033[1;32m")  # Set text color to green

print(r"""
   |___ /  __ _  ___(_) __| | | _| |__   __ _| (_) (_)
     |_ \ / _` |/ _ \ |/ _` | |/ / '_ \ / _` | | | | |
    ___) | (_| |  __/ | (_| |   <| | | | (_| | | | | |
   |____/ \__,_|\___|_|\__,_|_|\_\_| |_|\__,_|_|_|_|_|

    TeleGram ID : @s3aeidkhalili
""")

print("\033[0m")  # Reset text color

# Function to create an SSH tunnel
def create_ssh_tunnel(host, username, private_key_path):
    try:
        # Load the private key for authentication
        private_key = paramiko.RSAKey.from_private_key_file(private_key_path)

        # Connect to the server via SSH using the private key
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(host, username=username, pkey=private_key)

        # Create SSH tunnel
        transport = ssh_client.get_transport()
        channel = transport.open_channel('direct-tcpip', ('localhost', 8080), ('localhost', 8080))

        return channel

    except Exception as e:
        print(f"Error creating SSH tunnel: {e}")
        return None

# Function to generate an encryption key using scrypt
def generate_key(password, salt):
    return scrypt(password, salt, 32)  # Generate 256-bit key

# Function to encrypt data using AES-GCM
def encrypt_data(data, key):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + tag + ciphertext

# Function to compress data using zlib
def compress_data(data):
    return zlib.compress(data)

# Main function
def main():
    # Get input from the user
    host = input("Enter the destination server address (e.g., 192.168.1.10): ")
    port = int(input("Enter the SSH port (default 22): ") or 22)
    username = input("Enter the SSH username: ")
    private_key_path = input("Enter the path to the private SSH key: ")
    password = input("Enter the password for generating the encryption key: ").encode('utf-8')

    # Random salt for key generation
    salt = os.urandom(16)

    # Generate key from password and salt
    key = generate_key(password, salt)

    # Create SSH tunnel
    channel = create_ssh_tunnel(host, username, private_key_path)
    
    if channel:
        print("SSH tunnel successfully established.")
        
        # Data to be encrypted and sent
        data = input("Enter the data you want to send: ").encode('utf-8')
        
        # Compress the data
        compressed_data = compress_data(data)
        
        # Encrypt the data
        encrypted_data = encrypt_data(compressed_data, key)
        print(f"Encrypted data: {encrypted_data}")

        # Send encrypted data through the SSH tunnel
        channel.send(encrypted_data)
        print("Encrypted data sent.")
        
        # Close the tunnel
        channel.close()

if __name__ == "__main__":
    main()
