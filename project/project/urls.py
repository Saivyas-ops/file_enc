"""
URL configuration for project project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from app import views
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),

    path('',views.index,name='index'),
    path('reg',views.reg),
    path('userregistration',views.userregistration),
    path('logins',views.logins),
    path('logout',views.logout),
    path('userprofile',views.userprofile,name='userprofile'),
    path('update/<int:id>',views.update, name='update'),
    path('update/userupdates/<int:id>',views.userupdate, name='userupdate'),
    path('upload', views.upload_file),
    path('select/', views.select),
    path('history',views.history),
    path('decrypt',views.decrypt),
    path('select2/', views.select2),
    path('history2',views.history2),

]
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)