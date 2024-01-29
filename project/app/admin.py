from django.contrib import admin

# Register your models here.

from .models import User,EncryptedFile,DecryptionRequest




admin.site.register(User)
admin.site.register(EncryptedFile)
admin.site.register(DecryptionRequest)
