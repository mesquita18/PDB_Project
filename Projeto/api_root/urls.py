from django.contrib import admin
from django.urls import path,include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('',include('api_templates.urls')),
    path('api_templates',include('django.contrib.auth.urls')),
]
