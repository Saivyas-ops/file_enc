from django.db import models
from .encryption import generate_key, encrypt_file,decrypt_file
import os
import tempfile
import shutil


# Create your models here.

class User(models.Model):
    username=models.CharField(unique=True,max_length=200)
    email=models.CharField(unique=True,max_length=200)
    password=models.CharField(max_length=200)
    def __str__(self):
        return self.username
    




class EncryptedFile(models.Model):
    algorithm_choices = [
        ('hashes.SHA256', 'hashes.SHA256'),
        ('RSA', 'RSA'),
        ('AES', 'AES'),
        # Add more algorithms as needed
    ]
    user_id = models.ForeignKey(User, on_delete=models.CASCADE)
    file = models.FileField()
    password = models.CharField(max_length=100)
    algorith = models.CharField(max_length=20, choices=algorithm_choices)
    date = models.DateField(auto_now_add=True, null=True)
    publickey = models.TextField(max_length=512, null=True, blank=True)
    privatekey = models.TextField(max_length=512, null=True, blank=True)
    file_extension_name = models.TextField(max_length=512, null=True, blank=True)
    

    def save(self, *args, **kwargs):
        if not self.id:  # New instance being created
            super().save(*args, **kwargs)

            password_bytes = self.password.encode()
            salt = b'salt_'  # Change this to a proper salt value

            # Generate a key using the password and the chosen algorithm
            key = generate_key(password_bytes, self.algorith, salt)

            with open(self.file.path, 'rb') as file:
                file_content = file.read()

            if self.algorith == 'RSA':
                # Handle RSA-specific logic (if needed)
                pass
            else:
            # Encrypt the file content using the generated key and algorithm
                encrypted_content = encrypt_file(file_content, key, self.algorith)
            
                base_filename, file_extension = os.path.splitext(self.file.name)
                encrypted_filename = f"{base_filename}_encrypted{file_extension}"
                encrypted_file_path = os.path.join('uploads', encrypted_filename)

            # Save the encrypted content back to the file
                with open(encrypted_file_path, 'wb') as file:
                    file.write(encrypted_content)

                self.file.name = encrypted_filename

        super().save(*args, **kwargs)


    def __str__(self):
        return str(self.file)





class DecryptionRequest(models.Model):
    algorithm_choices = [
        ('hashes.SHA256', 'hashes.SHA256'),
        ('RSA', 'RSA'),
        ('AES', 'AES'), 
        # Add more algorithms as needed
    ]
    user_id = models.ForeignKey(User, on_delete=models.CASCADE)
    uploaded_file = models.FileField()
    password = models.CharField(max_length=100)
    algorith = models.CharField(max_length=20, choices=algorithm_choices)
    date = models.DateField(auto_now_add=True, null=True)  # Store the algorithm used for encryption


    def save(self, *args, **kwargs):
        if not self.id:  # New instance being created
            super().save(*args, **kwargs)

            password_bytes = self.password.encode()
            salt = b'salt_'  # Change this to a proper salt value

            # Generate a key using the password and the chosen algorithm
            key = generate_key(password_bytes, self.algorith, salt)

            with open(self.uploaded_file.path, 'rb') as file:
                file_content = file.read()

            if self.algorith == 'RSA':
                # Handle RSA-specific logic (if needed)
                pass
            else:
            

            # Decrypt the file content using the generated key and algorithm
                decrypted_content = decrypt_file(file_content, key, self.algorith)

                filename, extension = os.path.splitext(self.uploaded_file.name)

            # Construct the new filename for the decrypted file
                decrypted_filename = f"{filename}_decrypted{extension}"
                decrypted_file_path = os.path.join('uploads', decrypted_filename)
            


            # Use a temporary file for writing the decrypted content
                with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                    temp_file.write(decrypted_content)

            # Replace the original file with the decrypted content
                shutil.move(temp_file.name, decrypted_file_path)

                self.uploaded_file.name = decrypted_filename

        super().save(*args, **kwargs)
    

    def __str__(self):
        return str(self.uploaded_file)