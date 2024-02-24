from django.shortcuts import render,redirect
from django.http import HttpResponse
from  django.core.files.storage import FileSystemStorage
from django.conf import settings
from .encryption import decrypt_file
from .models import User
from .models import EncryptedFile
from .models import DecryptionRequest
from django.views.decorators.cache import cache_control
from django.contrib.auth import authenticate,login
from django.urls import reverse
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
import os
from pathlib import Path
# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent





def index(request):
    return render(request,'login.html')

def reg(request):
    return render(request,'register.html')


def userregistration(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        context={'message':'registerd successfully'}

        if User.objects.filter(username=username).exists():
            return render(request,'register.html',{'context':"Username already exists"})

        if User.objects.filter(email=email).exists():
            return render(request,'register.html',{'context':"Email already exists"})
        
        data = User(username=username,email=email,password=password)
        data.save()
        return render(request,'login.html')
    
    else:
        return render(request,'register.html')
    

def logins(request):
    username = request.POST.get('username')
    password = request.POST.get('password')
    context={'message':'Invalid User Credentials'}

    admin_user = authenticate(request,username=username,password=password)
    if admin_user is not None and admin_user.is_staff:
        login(request,admin_user)
        return redirect(reverse('admin:index'))

    if User.objects.filter(username=username,password=password).exists():
        userdetail=User.objects.get(username=request.POST['username'], password=password)
        if userdetail.password == request.POST['password']:
            request.session['uid'] = userdetail.id
            id=request.session['uid']
            if(id):
                return redirect(userprofile)
            else:
                return redirect(logins)

        else:
            return render(request,'login.html',context)
        
    else:
        return render(request, 'login.html', {'status': 'Invalid Username or Password'})
    

def logout(request):
    session_keys = list(request.session.keys())
    for key in session_keys:
      del request.session[key]
    return redirect(index)
    
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def userprofile(request):
    tem = request.session.get('uid')
    if tem:
        vpro = User.objects.get(id=tem)
        data = EncryptedFile.objects.filter(user_id=vpro)
        return render(request, 'landing.html', {'result': vpro,'data':data})
    else:
        # Handle the case when 'uid' doesn't exist in the session
        return redirect(logins)




def update(request,id):
    upt=User.objects.get(id=id)
    if(upt):
        return render(request,'profileedit.html',{'result':upt})


def userupdate(request,id):
    if request.method=="POST":
        email=request.POST.get('email')
        username = request.POST.get('username')
        password=request.POST.get('password')
        registration=User(username=username,email=email,password=password,id=id)
        registration.save()
        return redirect(userprofile)
    

def upload_file(request):
    if request.method == 'POST':
        tem=request.session['uid']
        vpro=User.objects.get(id=tem)
        uploaded_file = request.FILES.get('file')
        password = request.POST.get('password')
        algorith = request.POST.get('algorith')


        if algorith== 'RSA':
            filename_without_extension = os.path.splitext(uploaded_file.name)[0]
            filename_extension = os.path.splitext(uploaded_file.name)[1]
            # print(filename_extension,'----------------------------------------')
            # return True
            # print('-------------------------------------------------')
            # print(filename_without_extension)
            # print('-------------------------------------------------')
            publickey_name_with_pem=filename_without_extension+' public_key.pem'
            privatekey_name_with_pem=filename_without_extension+' private_key.pem'
            generate_rsa_key_pair(privatekey_name_with_pem,publickey_name_with_pem)
            # return true

            file_name_with_enc=filename_without_extension+'_encrypted'+'.enc'
            # print(file_name_with_enc,'----------------------------')
            # print(publickey_name_with_pem)

           
                 # Specify the complete file paths
            # public = os.path.join(directory_path, publickey_name_with_pem)
            # public_key_path = os.path.join(directory_path, public_key_path)
            


            encrypt_file_rsa(uploaded_file,file_name_with_enc,publickey_name_with_pem)

            

            if uploaded_file:  # Check if a file was uploaded
                # Retrieve the user from the session
                # with open(uploaded_file, 'rb') as file:
                #     file_data = file.read()
                # ciphertext, tag = cipher_aes.encrypt_and_digest(file_data)
                
                if vpro:
                    # Save the uploaded file to the model associated with the user
                    encrypted_file = EncryptedFile(user_id=vpro,file_extension_name=filename_extension, file=file_name_with_enc, password=password,algorith=algorith,publickey=publickey_name_with_pem,privatekey=privatekey_name_with_pem)

                    encrypted_file.save()

                    return redirect(userprofile)  # Redirect to the user profile page
                else:
                    return HttpResponse("error")
            else:
                return HttpResponse("<script>alert('no file uploaded'); window.location.href='/userprofile';</script>")
        else:
            if uploaded_file:  # Check if a file was uploaded
                # Retrieve the user from the session
                # with open(uploaded_file, 'rb') as file:
                #     file_data = file.read()
                # ciphertext, tag = cipher_aes.encrypt_and_digest(file_data)
                
                vpro=User.objects.get(id=tem)
                if vpro:
                    # Save the uploaded file to the model associated with the user
                    encrypted_file = EncryptedFile(user_id=vpro, file=uploaded_file, password=password,algorith=algorith)
                    encrypted_file.save()

                    return redirect(userprofile)  # Redirect to the user profile page
                else:
                    return HttpResponse("error")
    else:

        return redirect(userprofile)


def select(request):
    tem = request.session['uid']
    vpro = User.objects.get(id=tem)
    encrypted_files = EncryptedFile.objects.filter(user_id=vpro)
    return render(request,'select.html',{'encrypted_files': encrypted_files})

def history(request):
    tem = request.session['uid']
    vpro = User.objects.get(id=tem)
    encrypted_files = EncryptedFile.objects.filter(user_id=vpro)
    return render(request,'history.html',{'encrypted_files':encrypted_files})


 # Import your decryption function



def decrypt(request):
    tem = request.session.get('uid')
    if request.method == 'POST':
        
        uploaded_file = request.POST.get('file')
        password = request.POST.get('password')
        algorith = request.POST.get('algorithm')


        data = EncryptedFile.objects.get(id=uploaded_file)

        # 
        if algorith == 'RSA':
            if uploaded_file:  # Check if a file was uploaded
            # Retrieve the user from the session
            
                filename_with_extension = data.file
                filename_without_extension = os.path.splitext(filename_with_extension.name)[0]
                # print(filename_without_extension,'-----')
                # return True

                output_file_name = filename_without_extension+'_decrypted'+data.file_extension_name


                input_file_path = data.file.path  # Get the actual file path



                decrypt_file_rsa(input_file_path, output_file_name, data.privatekey)



                vpro=User.objects.get(id=tem)
            
                
                if vpro:
                    # Save the uploaded file to the model associated with the user
                    decrypted_file = DecryptionRequest(user_id=vpro, uploaded_file=output_file_name, password=password, algorith=algorith)
                    decrypted_file.save()






                    return redirect(userprofile)  # Redirect to the user profile page
                else:
                    return HttpResponse("error")
            else:
                    return HttpResponse("<script>alert('no file uploaded'); window.location.href='/userprofile';</script>")
        else:
            if uploaded_file:  # Check if a file was uploaded
            # Retrieve the user from the session
            





                vpro=User.objects.get(id=tem)
            
                
                if vpro:
                    # Save the uploaded file to the model associated with the user
                    decrypted_file = DecryptionRequest(user_id=vpro, uploaded_file=data.file, password=password, algorith=algorith)
                    decrypted_file.save()






                    return redirect(userprofile)  # Redirect to the user profile page
                else:
                    return HttpResponse("error")
            else:
                    return HttpResponse("<script>alert('no file uploaded'); window.location.href='/userprofile';</script>")
    else:
        return redirect(userprofile,{'data':data})


def decrypt_file_rsa(input_file_path, output_file_path, private_key_path):
    # print(input_file_path,'-----input_file_path')
    output_directory = os.path.join(BASE_DIR, 'uploads')
    # input_file_path__ = os.path.join(output_directory, private_key_path)
    output_file__ = os.path.join(output_directory, output_file_path)
    private_key_file__ = os.path.join(output_directory, private_key_path)

    # print(input_file_path__,'----------------start')

    # Read the encrypted data from the input file
    
    with open(input_file_path, 'rb') as encrypted_file:
        encrypted_symmetric_key = encrypted_file.read(256)  # Assuming 2048-bit RSA key
        nonce = encrypted_file.read(16)
        tag = encrypted_file.read(16)
        ciphertext = encrypted_file.read()

    # Import the RSA private key
    with open(private_key_file__, 'rb') as private_key_file:
        private_key = RSA.import_key(private_key_file.read())

    # Use RSA to decrypt the symmetric key
    cipher_rsa = PKCS1_OAEP.new(private_key)
    symmetric_key = cipher_rsa.decrypt(encrypted_symmetric_key)

    # Use the symmetric key to decrypt the file content
    cipher_aes = AES.new(symmetric_key, AES.MODE_EAX, nonce=nonce)
    decrypted_data = cipher_aes.decrypt_and_verify(ciphertext, tag)

    # Write the decrypted data to the output file
    with open(output_file__, 'wb') as decrypted_file:
        decrypted_file.write(decrypted_data)



def select2(request):
    tem = request.session['uid']
    vpro = User.objects.get(id=tem)
    decrypted_files = DecryptionRequest.objects.filter(user_id=vpro)
    return render(request,'select2.html',{'decrypted_files': decrypted_files})

# global__ras_private = ''

def generate_rsa_key_pair(private_key_path='private_key.pem', public_key_path='public_key.pem'):
                
                # 
            # Generate RSA key pair
                key = RSA.generate(2048)
                
                directory_path = os.path.join(BASE_DIR, 'uploads')
                 # Specify the complete file paths
                private_key_path = os.path.join(directory_path, private_key_path)
                public_key_path = os.path.join(directory_path, public_key_path)


                with open(private_key_path, 'wb') as private_key_file:
                    private_key_file.write(key.export_key())
                    # global__ras_private = private_key_file
                # Save public key
                with open(public_key_path, 'wb') as public_key_file:
                    public_key_file.write(key.publickey().export_key())

                return  private_key_file,public_key_file

def encrypt_file_rsa(uploaded_file,output_file, publickey_name_with_pem):
    # Import the RSA public key
    # print(uploaded_file,output_file, publickey_name_with_pem)
   
    output_directory = os.path.join(BASE_DIR, 'uploads')
    output_filepublickey_ = os.path.join(output_directory, publickey_name_with_pem)
    output_file_ = os.path.join(output_directory, output_file)


    # directory_path = os.path.join(BASE_DIR, 'uploads')
    # print(directory_path,'------------------------')
#                  # Specify the complete file paths
    # public_key_file__ = os.path.join(directory_path, public_key_file)
#                 public_key_path = os.path.join(directory_path, public_key_path)


    with open(output_filepublickey_, 'rb') as public_key_file:
        public_key = RSA.import_key(public_key_file.read())


    # Generate a random symmetric key
    symmetric_key = get_random_bytes(16)  # 128-bit key for AES

    # Use RSA to encrypt the symmetric key
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_symmetric_key = cipher_rsa.encrypt(symmetric_key)

    # Use the symmetric key to encrypt the file content
    cipher_aes = AES.new(symmetric_key, AES.MODE_EAX)
    file_data = uploaded_file.read() 
    ciphertext, tag = cipher_aes.encrypt_and_digest(file_data)

    # Write the encrypted symmetric key, nonce, tag, and ciphertext to the output file
    with open(output_file_, 'wb') as encrypted_file:
        encrypted_file.write(encrypted_symmetric_key)
        encrypted_file.write(cipher_aes.nonce)
        encrypted_file.write(tag)
        encrypted_file.write(ciphertext)

   






def history2(request):

    tem = request.session['uid']
    vpro = User.objects.get(id=tem)
    decrypted_files = DecryptionRequest.objects.filter(user_id=vpro)
    return render(request,'history2.html',{'decrypted_file':decrypted_files})