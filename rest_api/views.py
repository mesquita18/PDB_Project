from django.contrib.auth.models import User
from rest_framework import permissions, viewsets
from django.shortcuts import render,redirect
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework import status
from .models import UserSerializer,Disciplina,DisciplinaSerializer,Aluno,AlunoSerializer
from rest_framework.permissions import IsAuthenticated
from rest_framework.viewsets import ModelViewSet
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

def realizar_cadastro(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        email = request.POST.get('email')
        if User.objects.filter(username=username).exists():
            return render(request, 'usuarios/cadastro.html', {
                'error_message': 'Usuário com este username já existe!'
            })

        if User.objects.filter(email=email).exists():
            return render(request, 'usuarios/cadastro.html', {
                'error_message': 'O email já está cadastrado.'
            })
        user = User.objects.create(
            username=username,
            email=email,
            password=make_password(password)
        )
        return redirect('home.html')
    return render(request,'usuarios/cadastro.html',{'erro_message':'Bad request'})

def home(request):
    return render(request, 'usuarios/home.html')

@permission_classes([IsAuthenticated])
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

@login_required  # Exige que o usuário esteja logado para acessar
def visualizar_usuarios(request):
    usuarios = User.objects.all()  # Obtém todos os usuários cadastrados
    return render(request, 'usuarios/usuarios.html', {'usuarios': usuarios})

@permission_classes([IsAuthenticated])
def detalhar_disciplina(request,cod_disciplina):
    disciplina = get_object_or_404(Disciplina, cod_disciplina=cod_disciplina)
    return render(request, 'usuarios/disciplina.html', {'disciplina': disciplina})

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def visualizar_usuarios(request):
    usuarios = User.objects.all()
    # paginator = Paginator(usuarios, 10)
    # page_number = request.GET.get('page')
    # page_obj = paginator.get_page(page_number)
    return render(request, 'usuarios/usuarios.html', {'usuarios':usuarios})

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def visualizar_disciplinas(request):
    disciplinas = Disciplina.objects.all()
    paginator = Paginator(disciplinas, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    return render(request, 'usuarios/disciplinas.html', {'page_obj': page_obj})

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def visualizar_alunos(request):
    alunos = Aluno.objects.all()
    paginator = Paginator(alunos, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    return render(request, 'usuarios/alunos.html', {'page_obj': page_obj})

class AutenticarUser(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        token = request.data.get('token')
        if not token:
            return Response(status=status.HTTP_400_BAD_REQUEST)

        try:
            # Valida o token
            access_token = AccessToken(token)
            
            # Obtém o usuário associado ao token
            user_id = access_token['user_id']
            user = User.objects.get(id=user_id)
            
            # Retorna as informações do usuário
            return Response({
                "Username": user.username,
                "E-mail": user.email,
                "Nome completo": f"{user.first_name} {user.last_name}",
            })
        except:
            return Response(status=status.HTTP_401_UNAUTHORIZED)

class getUser(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = User.objects.all()
    serializer_class = UserSerializer
    http_method_names = ['get']

class getDisciplinas(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = Disciplina.objects.all()
    serializer_class = DisciplinaSerializer

class getAlunos(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = Aluno.objects.all()
    serializer_class = AlunoSerializer

@api_view(['GET'])
def get_by_cod(request,cod_disciplina):
    permission_classes = [IsAuthenticated]
    try:
        disciplina = Disciplina.objects.get(pk=cod_disciplina)
    except:
        return Response(status=status.HTTP_404_NOT_FOUND)
    if request.method == 'GET':
        serializer = DisciplinaSerializer(disciplina)
        return Response(serializer.data)

class TokenView(APIView):
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        # Autenticar o usuário
        user = authenticate(username=username, password=password)
        if user is not None:
            # Gerar os tokens JWT
            refresh = RefreshToken.for_user(user)
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            }, status=status.HTTP_200_OK)
        else:
            return Response(status=status.HTTP_400_BAD_REQUEST)

class ProtectedView(APIView):
    permission_classes = [IsAuthenticated]  # Requer que o usuário esteja autenticado

    def get(self, request):
        user = request.user  # O Django associa automaticamente o usuário autenticado ao request
        return Response({
            "message": "Token válido!",
            "username": user.username,
            "email": user.email,
        })

class getUserDetail(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        user = request.user  # Obter o usuário autenticado
        serializer = UserSerializer(user)
        return Response(serializer.data)

'''
url = "http://127.0.0.1:8000/usuarios/"
headers = {
    "Authorization": "Bearer <seu_token_jwt>"
}

response = requests.get(url, headers=headers)

try:
    response = requests.get(url, headers=headers)
    response.raise_for_status()  # Levanta uma exceção para status >= 400
    print(response.json())
except requests.exceptions.RequestException as e:
    print("Erro na requisição:", e)

@api_view(['POST'])
def login_view(request):
    username = request.data.get('username')
    password = request.data.get('password')
    user = authenticate(username=username, password=password)
    if user is not None:
        token_payload = {
            'id': user.id,
            'username': user.username,
            'exp': datetime.utcnow() + timedelta(hours=2400),
        }
        token = jwt.encode(token_payload, settings.SECRET_KEY, algorithm='HS256')
        return Response({'token': token}, status=status.HTTP_200_OK)
    else:
        return Response({'error': 'Credenciais inválidas'}, status=status.HTTP_401_UNAUTHORIZED)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def listar_usuarios_view(request):
    usuarios = User.objects.all().values('id', 'username', 'email', 'is_staff')
    return Response(usuarios, status=200)
'''