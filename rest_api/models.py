from django.db import models
from django.contrib.auth.models import User
from rest_framework import serializers
from rest_framework.permissions import IsAuthenticated

class Disciplina(models.Model):
    permission_classes = [IsAuthenticated]
    cod_disciplina = models.CharField(primary_key=True,max_length=10)
    nome_disciplina = models.CharField(max_length=100,default='')
    carga_horaria = models.IntegerField(default=0)
    periodo = models.IntegerField(default=0)

# class Professor

class UserSerializer(serializers.ModelSerializer):
    permission_classes = [IsAuthenticated]
    class Meta:
        model = User
        fields = ['id', 'username']

class DisciplinaSerializer(serializers.ModelSerializer):
    permission_classes = [IsAuthenticated]
    class Meta:
        model = Disciplina
        fields = '__all__'