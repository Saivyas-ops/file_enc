# encryption.py
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP







def generate_key(password, algorith, salt):
    # Convert algorithm string to the actual algorithm object
    if algorith == 'hashes.SHA256':
        kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return key
        
    elif algorith == 'RSA':
        # Generate an RSA key pair
        private_key = RSA.generate(2048)
        key = private_key.export_key()
        return key
    elif algorith == 'AES':
        # Use a key derivation function for AES
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # Use 32 bytes (256 bits) for AES-256
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password)
        return key
    else:
        # Handle the case when an invalid algorithm is provided
        raise ValueError("Invalid algorithm")
    
    



def encrypt_file(file_content, key,algorith):
    if algorith == 'AES':
        # Generate a random initialization vector
        iv = get_random_bytes(16)
        # Create AES cipher object with CBC mode
        cipher = AES.new(key, AES.MODE_CBC, iv)
        # Pad the file content to fit the block size
        padded_content = pad(file_content, AES.block_size)
        # Encrypt the content
        encrypted_content = cipher.encrypt(padded_content)
        # Return the IV and encrypted content
        return iv + encrypted_content
    elif algorith == 'RSA':
        # Use RSA to encrypt a symmetric key (AES key)
        rsa_key = RSA.generate(2048)  # Use a larger key size
        session_key = get_random_bytes(16)  # Use 128 bits for AES-128
        cipher_rsa = PKCS1_OAEP.new(rsa_key)
        encrypted_session_key = cipher_rsa.encrypt(session_key)

        # Use the symmetric key to encrypt the file content
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        encrypted_content, tag = cipher_aes.encrypt_and_digest(file_content)

        

        # Return the encrypted symmetric key, nonce, tag, and encrypted content
        return encrypted_session_key + cipher_aes.nonce + tag + encrypted_content
    else:
        f = Fernet(key)
        encrypted_content = f.encrypt(file_content)
        return encrypted_content
    


def decrypt_file(encrypted_content, key,algorith):
    if algorith == 'AES':
        # Extract the IV from the encrypted content
        iv = encrypted_content[:16]

        # Create AES cipher object with CBC mode
        cipher = AES.new(key, AES.MODE_CBC, iv)

        # Decrypt the content
        decrypted_content = cipher.decrypt(encrypted_content[16:])

        # Unpad the decrypted content
        unpadded_content = unpad(decrypted_content, AES.block_size)

        # Return the decrypted content
        return unpadded_content
    
    elif algorith == 'RSA':
        rsa_key = RSA.import_key(key)

        # Extract the encrypted session key, nonce, tag, and encrypted content
        rsa_key_size = rsa_key.size_in_bytes()
        print(f"RSA Key Size: {rsa_key.size_in_bits()} bits")

        encrypted_session_key = encrypted_content[:rsa_key_size]
        nonce = encrypted_content[rsa_key_size:rsa_key_size + 16]
        tag = encrypted_content[rsa_key_size + 16:rsa_key_size + 32]
        encrypted_file_content = encrypted_content[rsa_key_size + 32:]

        print(f"Encrypted Session Key: {len(encrypted_session_key)}")
        print(f"Nonce: {len(nonce)}")
        print(f"Tag: {len(tag)}")
        print(f"Encrypted File Content: {len(encrypted_file_content)}")

        # Use RSA to decrypt the session key
        cipher_rsa = PKCS1_OAEP.new(rsa_key)
        try:
            session_key = cipher_rsa.decrypt(encrypted_session_key)
        except ValueError as e:
            print(f"Error during RSA decryption: {e}")
            raise

        # Use the decrypted session key to decrypt the content
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce=nonce)
        decrypted_content = cipher_aes.decrypt_and_verify(encrypted_file_content, tag)

        return decrypted_content
    else:
        f = Fernet(key)
        decrypted_content = f.decrypt(encrypted_content)
        return decrypted_content



