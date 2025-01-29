from django.contrib.auth.models import User
from django.db.models import Q
from django.contrib.auth import logout
from rest_framework.response import Response
from .models import UserSerializer,Disciplina,DisciplinaSerializer,Aluno,AlunoSerializer,Nota,NotaSerializer,Turma,TurmaSerializer,AlunoTurma,AlunoTurmaSerializer
from django.contrib.auth import authenticate,login
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.contrib.auth.hashers import make_password
from django.shortcuts import render, redirect , get_object_or_404
from django.contrib import messages
from collections import defaultdict
from django.db import transaction
from django.utils.safestring import mark_safe
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

@login_required
def realizar_logout(request):
    logout(request)
    return render(request,'usuarios/logout.html')

def login_error(request):
    return render(request,'usuarios/login-error.html')

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
        with transaction.atomic():
            AlunoTurma.objects.filter(turma=turma).delete()
            for aluno in alunos_selecionados:
                AlunoTurma.objects.create(turma=turma, aluno=aluno)
                Nota.objects.get_or_create(
                    aluno=aluno,
                    turma=turma,
                )
        messages.success(request, 'Turma atualizada!')
        return redirect('listar_turmas')

@login_required
def historico_aluno(request, aluno_id):
    aluno = get_object_or_404(Aluno, id=aluno_id)
    notas = Nota.objects.filter(aluno=aluno).select_related('turma__disciplina')
    notas_por_periodo = defaultdict(list)
    for nota in notas:
        periodo = nota.turma.semestre
        notas_por_periodo[periodo].append({
            'nome': nota.turma.disciplina.nome_disciplina,
            'nota1': nota.nota1,
            'nota2': nota.nota2,
            'nota3': nota.nota3,
            'final': nota.final,
            'media': nota.media,
            'media_final':nota.media_final,
            'status':nota.status
        })

    notas_por_periodo = dict(sorted(notas_por_periodo.items()))

    context = {
        'aluno': aluno,
        'notas_por_periodo': notas_por_periodo,
    }
    return render(request, 'usuarios/historico-aluno.html', context)

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
    search_query = request.GET.get('search', '').strip()
    usuarios = User.objects.all()
    if search_query:
        usuarios = usuarios.filter(Q(username__icontains=search_query))
        for usuario in usuarios:
            pattern = re.compile(re.escape(search_query), re.IGNORECASE)
            usuario.username = mark_safe(
                pattern.sub(
                    lambda match: f'<span style="background-color: yellow; font-weight: bold;">{match.group(0)}</span>',
                    usuario.username
                )
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
    search_query = request.GET.get('search', '').strip()
    disciplinas = Disciplina.objects.all().order_by('periodo')

    if search_query:
        disciplinas = disciplinas.filter(
            Q(nome_disciplina__icontains=search_query)
        )
    
        for disciplina in disciplinas:
            pattern = re.compile(re.escape(search_query), re.IGNORECASE)
            disciplina.nome_disciplina = mark_safe(
                pattern.sub(
                    lambda match: f'<span style="background-color: yellow; font-weight: bold;">{match.group(0)}</span>',
                    disciplina.nome_disciplina
                )
            )

    paginator = Paginator(disciplinas, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    return render(request, 'usuarios/disciplinas.html', {
        'page_obj': page_obj,
        'search_query': search_query
    })

@login_required
def visualizar_turmas(request):
    search_query = request.GET.get('search', '').strip()
    turmas = Turma.objects.all().order_by('semestre')
    if search_query:
        turmas = turmas.filter(Q(disciplina__nome_disciplina__icontains=search_query))
        for turma in turmas:
            pattern = re.compile(re.escape(search_query), re.IGNORECASE)
            turma.disciplina.nome_disciplina = mark_safe(
                pattern.sub(
                    lambda match: f'<span style="background-color: yellow; font-weight: bold;">{match.group(0)}</span>',
                    turma.disciplina.nome_disciplina
                )
            )
    paginator = Paginator(turmas, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    return render(request, 'usuarios/turmas.html', {'page_obj': page_obj,'search-query':search_query})

@login_required
def visualizar_alunos(request):
    search_query = request.GET.get('search', '').strip()
    alunos = Aluno.objects.all().order_by('nome')
    if search_query:
        alunos = alunos.filter(Q(nome__icontains=search_query))
        for aluno in alunos:
            pattern = re.compile(re.escape(search_query), re.IGNORECASE)
            aluno.nome = mark_safe(
                pattern.sub(
                    lambda match: f'<span style="background-color: yellow; font-weight: bold;">{match.group(0)}</span>',
                    aluno.nome
                )
            )
    paginator = Paginator(alunos, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    return render(request, 'usuarios/alunos.html', {'page_obj': page_obj, 'search_query': search_query})

@login_required
def listar_notas_turma(request, turma_id):
    if request.method == 'GET':
        turma = get_object_or_404(Turma, id=turma_id)
        notas = Nota.objects.filter(turma=turma)
        notas_dict = {nota.aluno.id: nota for nota in notas}
        alunos_turma = AlunoTurma.objects.filter(turma=turma).select_related('aluno')
        paginator = Paginator(alunos_turma, 5)
        page_number = request.GET.get('page', 1)
        page_obj = paginator.get_page(page_number)
        return render(request, 'usuarios/notas-alunos.html', {
            'turma': turma,
            'page_obj': page_obj,
            'notas_dict': notas_dict,
        })
    if request.method == 'POST':
        turma = get_object_or_404(Turma, id=turma_id)
        alunos_turma = AlunoTurma.objects.filter(turma=turma)
        notas = Nota.objects.filter(turma=turma)
        for aluno_turma in alunos_turma:
            nota = notas.filter(aluno=aluno_turma.aluno).first()
            if not nota:
                nota = Nota.objects.create(aluno=aluno_turma.aluno, turma=turma)
            def parse_float(value, previous_value):
                if value == '':
                    return previous_value
                try:
                    return float(value)
                except ValueError:
                    return previous_value
            nota1 = parse_float(request.POST.get(f'nota1_{aluno_turma.aluno.id}'), nota.nota1)
            nota2 = parse_float(request.POST.get(f'nota2_{aluno_turma.aluno.id}'), nota.nota2)
            nota3 = parse_float(request.POST.get(f'nota3_{aluno_turma.aluno.id}'), nota.nota3)
            final = parse_float(request.POST.get(f'final_{aluno_turma.aluno.id}'), nota.final)
            if (
                nota1 != nota.nota1 or
                nota2 != nota.nota2 or
                nota3 != nota.nota3 or
                final != nota.final
            ):
                nota.nota1 = nota1
                nota.nota2 = nota2
                nota.nota3 = nota3
                nota.final = final
                nota.save()
        return redirect('listar_turmas')