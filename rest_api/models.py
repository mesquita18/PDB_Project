from django.db import models
from django.contrib.auth.models import User
from rest_framework import serializers
from rest_framework.permissions import IsAuthenticated
from django.core.exceptions import ValidationError
import re

def calcular_digito(cpf, peso):
    soma = sum(int(cpf[i]) * peso for i, peso in enumerate(range(peso, 1, -1)))
    resto = soma % 11
    return '0' if resto < 2 else str(11 - resto)

def validar_cpf(cpf):
    cpf = re.sub(r'\D', '', cpf)
    if len(cpf) != 11 or not cpf.isdigit():
        raise ValidationError("CPF deve conter 11 dígitos numéricos.")
    if cpf == cpf[0] * 11:
        raise ValidationError("CPF inválido.")
    if cpf[9] != calcular_digito(cpf[:9], 10):
        raise ValidationError("CPF inválido.")
    if cpf[10] != calcular_digito(cpf[:10], 11):
        raise ValidationError("CPF inválido.")

class Disciplina(models.Model):
    permission_classes = [IsAuthenticated]
    cod_disciplina = models.CharField(primary_key=True,max_length=10)
    nome_disciplina = models.CharField(max_length=100,default='')
    carga_horaria = models.IntegerField(default=0)
    periodo = models.IntegerField(default=0)

class Aluno(models.Model):
    permission_classes = [IsAuthenticated]
    nome = models.CharField(max_length=200,default='')
    cpf = models.CharField(max_length=11, validators=[validar_cpf])

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

class AlunoSerializer(serializers.ModelSerializer):
    permission_classes = [IsAuthenticated]
    class Meta:
        model = Aluno
        fields = ['nome', 'cpf']
    def valida_cpf(self, data):
        if Aluno.objects.filter(cpf=data['cpf']).exclude(nome=data['nome']).exists():
            raise serializers.ValidationError("CPF já cadastrado para outro nome.")
        return data