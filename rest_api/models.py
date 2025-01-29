from django.db import models
from django.contrib.auth.models import User
from rest_framework import serializers
from rest_framework.permissions import IsAuthenticated
from django.core.exceptions import ValidationError
from django.core.validators import RegexValidator
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
    periodo = models.CharField(max_length=5,default='')

    def __str__(self):
        return self.nome_disciplina

class Aluno(models.Model):
    permission_classes = [IsAuthenticated]
    nome = models.CharField(max_length=200,default='')
    cpf = models.CharField(
        max_length=14,
        validators=[
            RegexValidator(
                regex=r'^\d{3}.\d{3}.\d{3}-\d{2}$',
                message="O formato do CPF deve ser 'xxx.xxx.xxx-xx'."
            )
        ]
    )

class Turma(models.Model):
    permission_classes = [IsAuthenticated]
    disciplina = models.ForeignKey(
        Disciplina,
        on_delete=models.CASCADE,
        related_name='turmas'
    )
    semestre = models.CharField(
        max_length=7,
        validators=[
            RegexValidator(
                regex=r'^\d{4}-\d{2}$',
                message="O formato do semestre deve ser 'xxxx-xx'."
            )
        ]
    )
    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=['disciplina', 'semestre'],
                name='unique_disciplina_semestre'
            )
        ]

class AlunoTurma(models.Model):
    aluno = models.ForeignKey('Aluno', on_delete=models.CASCADE, related_name="turmas")
    turma = models.ForeignKey('Turma', on_delete=models.CASCADE, related_name="alunos")
    class Meta:
        unique_together = ('aluno', 'turma')

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

class TurmaSerializer(serializers.ModelSerializer):
    disciplina = serializers.SlugRelatedField(queryset=Disciplina.objects.all(), slug_field='cod_disciplina')
    alunos = serializers.ListField(
        child=serializers.IntegerField(),
        write_only=True,
        help_text="IDs dos alunos que fazem parte da turma."
    )
    class Meta:
        model = Turma
        fields = ['disciplina', 'semestre', 'alunos','notas']
    def get_notas(self, obj):
        notas = Nota.objects.filter(turma=obj).values('aluno__nome', 'nota')
        return list(notas)
    def create(self, validated_data):
        alunos_ids = validated_data.pop('alunos', [])
        turma = Turma.objects.create(**validated_data)
        if alunos_ids:
            alunos = Aluno.objects.filter(id__in=alunos_ids)
            turma.alunos.set(alunos)
        return turma
    def update(self, instance, validated_data):
        alunos_ids = validated_data.pop('alunos', [])
        instance = super().update(instance, validated_data)
        AlunoTurma.objects.filter(turma=instance).delete()
        for aluno_id in alunos_ids:
            AlunoTurma.objects.create(aluno_id=aluno_id, turma=instance)
        return instance
    def validate_semestre(self, value):
        if not re.match(r'^\d{4}-\d{2}$', value):
            raise serializers.ValidationError("O semestre deve estar no formato 'xxxx-xx', por exemplo, '2024-01'.")
        return value
    def validate(self, data):
        if Turma.objects.filter(disciplina=data['disciplina'], semestre=data['semestre']).exists():
            raise serializers.ValidationError("Já existe uma turma para esta disciplina neste semestre.")
        return data
class AlunoTurmaSerializer(serializers.ModelSerializer):
    alunos = serializers.SerializerMethodField()
    turma = serializers.SerializerMethodField()
    semestre = serializers.CharField(source='turma.semestre', read_only=True)
    def get_alunos(self, obj):
        alunos = Aluno.objects.filter(turmas__turma=obj.id).values_list('nome', flat=True)
        return list(alunos)
    def get_turma(self, obj):
        return obj.turma.disciplina.nome_disciplina
    class Meta:
        model = AlunoTurma
        fields = ['turma','semestre','alunos']

class Nota(models.Model):
    aluno = models.ForeignKey(Aluno, on_delete=models.CASCADE, related_name='notas')
    turma = models.ForeignKey(Turma, on_delete=models.CASCADE, related_name='notas')
    nota1 = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True, default=None)
    nota2 = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True, default=None)
    nota3 = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True, default=None)
    final = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True, default=None)
    _status = models.CharField(max_length=20, default="PENDENTE", editable=False)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=['aluno', 'turma'],
                name='unique_aluno_turma_nota'
            )
        ]

    @property
    def media(self):
        notas = [self.nota1, self.nota2, self.nota3]
        notas_validas = [nota for nota in notas if nota is not None]
        if len(notas_validas) >= 2:
            maiores_notas = sorted(notas_validas, reverse=True)[:2]
            return round(sum(maiores_notas) / 2, 2)
        return None

    @property
    def media_final(self):
        if self.media is not None and self.final is not None:
            return round((self.media + self.final) / 2, 2)
        elif self.media >=7.0:
            self.final=0.0
        return self.media if self.media is not None else None

    @property
    def status(self):
        if self.media is None:
            return "PENDENTE"
        if self.media >= 7:
            return "APROVADO"
        elif self.media >= 4:
            if self.final is None:
                return "PENDENTE"
            return "APROVADO" if self.media_final >= 5 else "REPROVADO"
        return "REPROVADO"

    def save(self, *args, **kwargs):
        self._status = self.status
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.aluno.nome} - {self.turma.disciplina.nome_disciplina} ({self.status})"

class NotaSerializer(serializers.ModelSerializer):
    aluno_nome = serializers.CharField(source='aluno.nome', read_only=True)
    turma_disciplina = serializers.CharField(source='turma.disciplina.nome_disciplina', read_only=True)
    media = serializers.ReadOnlyField()
    media_final = serializers.ReadOnlyField()
    status = serializers.ReadOnlyField()
    _status = serializers.ReadOnlyField()

    class Meta:
        model = Nota
        fields = ['aluno', 'turma', 'nota1', 'nota2', 'nota3', 'final', 'media', 'media_final', 'status', '_status']