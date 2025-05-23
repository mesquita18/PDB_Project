from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.db import models

class MyProfile(models.Model):
    user = models.OneToOneField(User,on_delete=models.CASCADE, related_name='profile')
    description = models.CharField(max_length=100)

@receiver(post_save, sender=User)
def my_handler(sender, **kwargs):
    if kwargs.get('created', False):
        MyProfile.objects.create(user=kwargs['instance'])