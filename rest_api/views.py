from django.contrib.auth.models import User
from django.db.models import Q
from rest_framework import permissions, viewsets
from django.shortcuts import render,redirect
from rest_framework.decorators import api_view,permission_classes,action
from rest_framework.response import Response
from rest_framework import status
from .models import UserSerializer,Disciplina,DisciplinaSerializer,Aluno,AlunoSerializer
from rest_framework.permissions import IsAuthenticated
from rest_framework.viewsets import ModelViewSet,ReadOnlyModelViewSet
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.permissions import AllowAny
from django.contrib.auth import authenticate,login
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ValidationError
from rest_framework_simplejwt.tokens import AccessToken
from django.shortcuts import render, get_object_or_404
from django.core.paginator import Paginator
from django.http import HttpResponse
import json,jwt,requests
from django.conf import settings
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password
from django.shortcuts import render, redirect
from django.http import HttpResponse
from .models import Turma,TurmaSerializer,AlunoTurma,AlunoTurmaSerializer
from django.db.models import Count
from django.contrib import messages
import re

@login_required
def realizar_cadastro(request):
    if request.method == 'GET':
        return render(request,'usuarios/cadastro.html')
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        email = request.POST.get('email')
        if User.objects.filter(username=username).exists() :
            return render(request, 'usuarios/cadastro.html', {'error_message': 'Usuário já existe com esse Username!'})
        if email and User.objects.filter(email=email).exists():
            return render(request, 'usuarios/cadastro.html', {'error_message': 'Usuário com esse e-mail já está cadastrado!'})
        User.objects.create_user(
            username=username,
            password=make_password(password),
            email=email if email else None,
        )
        return render(request,'usuarios/cadastro.html',{'message':'Usuário cadastrado com sucesso!'})

@login_required
def home(request):
    return render(request, 'usuarios/home.html')

@login_required
def criar_turma(request):
    if request.method == 'GET':
        disciplinas = Disciplina.objects.all()
        alunos = Aluno.objects.all()
        return render(request,'usuarios/criar-turma.html',{'alunos': alunos,'disciplinas':disciplinas})
    if request.method == 'POST':
        semestre = request.POST.get('semestre')
        cod_disciplina = request.POST.get('cod_disciplina')
        alunos_ids = request.POST.getlist('alunos')
        try:
            disciplina = Disciplina.objects.get(cod_disciplina=cod_disciplina)
        except Disciplina.DoesNotExist:
            return render(request,'usuarios/criar-turma.html',{'error_message':'Disciplina não encontrada!'})
        if Turma.objects.filter(disciplina=disciplina, semestre=semestre).exists():
            return render(request,'usuarios/criar-turma.html',{'error_message':'Já existe uma turma para essa disciplina no semestre informado.'})
        nova_turma = Turma.objects.create(disciplina=disciplina, semestre=semestre)
        alunos = Aluno.objects.filter(id__in=alunos_ids)
        if not alunos.exists():
            return render(request,'usuarios/criar-turma.html',{'error_message':'Nenhum aluno foi selecionado!'})
        for aluno in alunos:
            AlunoTurma.objects.create(aluno=aluno, turma=nova_turma)
        return render(request,'usuarios/criar-turma.html',{'message':'Turma cadastrada!'})

@login_required
def cadastro_aluno(request):
    if request.method == 'GET':
        return render(request, 'usuarios/cadastro-aluno.html')
    if request.method == 'POST':
        nome = request.POST.get('nome')
        cpf = request.POST.get('cpf')
        cpf_regex = r'^\d{3}\.\d{3}\.\d{3}-\d{2}$'
        if not re.match(cpf_regex, cpf):
            return render(request, 'usuarios/cadastro-aluno.html', {
                'erro': 'CPF inválido! O formato deve ser xxx.xxx.xxx-xx.'
            })
        if Aluno.objects.filter(cpf=cpf).exists():
            return render(request, 'usuarios/cadastro-aluno.html', {
                'erro': 'Aluno já está matriculado!'
            })
        Aluno.objects.create(
            nome=nome,
            cpf=cpf,
        )
        return render(request, 'usuarios/cadastro-aluno.html', {
            "message": "Aluno matriculado!"
        })

@login_required
def realizar_login(request):
    if request.method == 'GET':
        return render(request,'usuarios/login.html')
    elif request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(username=username, password=password)
        if user is not None:
            login(request,user)
            return redirect('usuarios/home.html')
        return render(request, 'usuarios/login.html', {
            'erro': 'Usuário ou senha inválidos!'
        })
    else:
        return render(request, 'usuarios/login.html', {
            'erro': 'Bad Request!'
        })

@login_required
def modificar_turma(request,cod_disciplina,semestre):
    turma = get_object_or_404(Turma, disciplina__cod_disciplina=cod_disciplina,semestre=semestre)
    alunos = Aluno.objects.all().order_by('nome')
    alunos_na_turma = AlunoTurma.objects.filter(turma=turma)
    alunos_cadastrados = alunos.filter(id__in=alunos_na_turma.values('aluno_id'))
    alunos_nao_cadastrados = alunos.exclude(id__in=alunos_na_turma.values('aluno_id'))
    if request.method == "GET":
        context = {
            'cod_disciplina': cod_disciplina,
            'semestre': semestre,
            'alunos_cadastrados': alunos_cadastrados,
            'alunos_nao_cadastrados': alunos_nao_cadastrados,
            'alunos': alunos,
        }
        return render(request,'usuarios/modificar-turma.html',context)
    if request.method == "POST":
        alunos_ids = request.POST.getlist("alunos")
        alunos_selecionados = Aluno.objects.filter(id__in=alunos_ids)
        AlunoTurma.objects.filter(turma=turma).delete()
        for aluno in alunos_selecionados:
            AlunoTurma.objects.create(turma=turma, aluno=aluno)
        return render(request, "usuarios/home.html",{'message':'Turma atualizada!'})

@login_required
def cadastrar_disciplina(request):
    if request.method == "POST":
        cod_disciplina = request.POST.get("cod_disciplina")
        nome_disciplina = request.POST.get("nome_disciplina")
        carga_horaria = request.POST.get("carga_horaria")
        periodo = request.POST.get("periodo")
        if not all([cod_disciplina, nome_disciplina, carga_horaria, periodo]):
            return render(request, 'usuarios/cadastrar-disciplina.html', {'erro': 'Todos os campos são obrigatórios!'})
        try:
            if Disciplina.objects.filter(cod_disciplina=cod_disciplina).exists():
                return render(
                    request, 
                    'usuarios/cadastrar-disciplina.html', 
                    {'erro': f"A disciplina com código {cod_disciplina} já existe!"}
                )
            nova_disciplina = Disciplina(
                cod_disciplina=cod_disciplina,
                nome_disciplina=nome_disciplina,
                carga_horaria=carga_horaria,
                periodo=periodo,
            )
            nova_disciplina.save()
            return render(request, 'usuarios/cadastrar-disciplina.html', {'message': f"Disciplina '{nome_disciplina}' cadastrada!"})
        except Exception as e:
            return render(request, 'usuarios/cadastrar-disciplina.html', {'erro': f"Erro ao cadastrar disciplina: {str(e)}"})
    return render(request, 'usuarios/cadastrar-disciplina.html')

@login_required
def visualizar_usuarios(request):
    search_query = request.GET.get('search', '')
    usuarios = User.objects.all()
    if search_query:
        usuarios = usuarios.filter(
            Q(username__icontains=search_query)
        )
    paginator = Paginator(usuarios, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    return render(request, 'usuarios/usuarios.html', {'page_obj': page_obj,'search_query':search_query})

@login_required
def detalhar_disciplina(request,cod_disciplina):
    disciplina = get_object_or_404(Disciplina, cod_disciplina=cod_disciplina)
    return render(request, 'usuarios/disciplina.html', {'disciplina': disciplina})

@login_required
def detalhar_turma(request,id_turma):
    turma = get_object_or_404(Turma, id=id_turma)
    alunos = AlunoTurma.objects.filter(turma=turma)
    return render(request, 'usuarios/turma.html', {'turma': turma, 'alunos': alunos})

@login_required
def visualizar_disciplinas(request):
    search_query = request.GET.get('search', '')
    disciplinas = Disciplina.objects.all().order_by('periodo')
    if search_query:
        disciplinas = disciplinas.filter(
            Q(nome_disciplina__icontains=search_query)
        )
    paginator = Paginator(disciplinas, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    return render(request, 'usuarios/disciplinas.html', {'page_obj': page_obj,'search_query': search_query})

@login_required
def visualizar_turmas(request):
    search_query = request.GET.get('search', '')
    turmas = Turma.objects.all().order_by('semestre')
    if search_query:
        turmas = turmas.filter(Q(disciplina__nome_disciplina__icontains=search_query))
    paginator = Paginator(turmas, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    return render(request, 'usuarios/turmas.html', {'page_obj': page_obj,'search-query':search_query})

@login_required
def visualizar_alunos(request):
    search_query = request.GET.get('search', '')
    alunos = Aluno.objects.all().order_by('nome')
    if search_query:
        alunos = alunos.filter(Q(nome__icontains=search_query))
    paginator = Paginator(alunos, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    return render(request, 'usuarios/alunos.html', {'page_obj': page_obj, 'search_query': search_query})