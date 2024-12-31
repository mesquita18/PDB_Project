from django.contrib.auth.models import User
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

class AlunoTurmaViewSet(ReadOnlyModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = AlunoTurma.objects.all()
    serializer_class = AlunoTurmaSerializer

class AlunoTurmaViewSetByCod(viewsets.ReadOnlyModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = Turma.objects.all()
    serializer_class = TurmaSerializer
    lookup_field = 'cod_disciplina'  # Use 'cod_disciplina' como campo de pesquisa
    def get_queryset(self):
        # Se necessário, personalize o queryset aqui
        cod_disciplina = self.kwargs.get(self.lookup_field)  # Obtém o valor do código da disciplina
        if cod_disciplina:
            return Turma.objects.filter(disciplina__cod_disciplina=cod_disciplina)
        return super().get_queryset()

class CriarTurmaView(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = Turma.objects.all()
    serializer_class = TurmaSerializer
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        turma = serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    @action(detail=True, methods=['put'], url_path='atualizar-alunos')
    def put(self,request,pk=None):
        turma = self.get_object()
        alunos_turma = AlunoTurma.objects.filter(turma=turma)
        alunos_turma.delete()
        novos_alunos = request.data.get('alunos',[])
        alunos = Aluno.objects.filter(id__in=alunos_ids)
        turma.alunos.set(alunos)  # Atualiza a relação Many-to-Many
        turma.save()
        return Response(TurmaSerializer(turma).data)

class AtualizarTurmaView(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = Turma.objects.all()
    serializer_class = TurmaSerializer
    def put(self, request, pk=None):
        # Obtenha a turma pelo ID (pk)
        turma = self.get_object()
        aluno_turma_relations = AlunoTurma.objects.filter(turma=turma)
        # Conta as relações antes de excluir
        total_relations = aluno_turma_relations.count()
        # Exclui as relações
        aluno_turma_relations.delete()
        # Obtenha os IDs dos alunos passados na requisição
        alunos_ids = request.data.get('alunos', [])
        # Verifique se os IDs dos alunos são válidos
        alunos = Aluno.objects.filter(id__in=alunos_ids)
        # Atribua os alunos à turma
        turma.alunos.set(alunos)  # Atualiza a relação Many-to-Many
        turma.save()
        # Retorne a resposta com os dados da turma atualizada
        return Response(TurmaSerializer(turma).data)

@permission_classes([IsAuthenticated])
def realizar_cadastro(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        email = request.POST.get('email')
        if User.objects.filter(username=username).exists() or User.objects.filter(email=email).exists():
            return render(request, 'usuarios/cadastro.html', {
                'error_message': 'Usuário já existe!'
            })
        
        user = User.objects.create(
            username=username,
            email=email,
            password=make_password(password)
        )
        return render(request,'usuarios/home.html')
    return render(request,'usuarios/cadastro.html',{'erro_message':'Bad request'})

class CadastrarAluno(APIView):
    @permission_classes([IsAuthenticated])
    def cadastrar_aluno(self,request):
        if request.method == 'POST':
            nome = request.data.get('nome')
            cpf = request.data.get('cpf')
            if Aluno.objects.filter(cpf=cpf).exists():
                return Response(status=status.HTTP_406_NOT_ACCEPTABLE)
            aluno = Aluno.objects.create(
                nome=nome,
                cpf=cpf,
            )
            return Response(AlunoSerializer(aluno),status=status.HTTP_201_CREATED)
        return Response(status=status.HTTP_400_BAD_REQUEST)

@permission_classes([IsAuthenticated])
def home(request):
    return render(request, 'usuarios/home.html')

@permission_classes([IsAuthenticated])
def criar_turma(request):
    if request.method == 'GET':
        alunos = Aluno.objects.all()
        return render(request,'usuarios/criar-turma.html',{'alunos': alunos})
    if request.method == 'POST':
        semestre = request.POST.get('semestre')
        cod_disciplina = request.POST.get('cod_disciplina')
        alunos_ids = request.POST.getlist('alunos')
        try:
            disciplina = Disciplina.objects.get(cod_disciplina=cod_disciplina)
        except Disciplina.DoesNotExist:
            return HttpResponse("Disciplina não encontrada.", status=404)
        if Turma.objects.filter(disciplina=disciplina, semestre=semestre).exists():
            return HttpResponse("Já existe uma turma para essa disciplina no semestre informado.", status=400)
        nova_turma = Turma.objects.create(disciplina=disciplina, semestre=semestre)
        alunos = Aluno.objects.filter(id__in=alunos_ids)
        if not alunos.exists():
            return HttpResponse("Nenhum aluno válido foi selecionado.", status=400)
        for aluno in alunos:
            AlunoTurma.objects.create(aluno=aluno, turma=nova_turma)
        return render(request,'usuarios/criar-turma.html')

@permission_classes([IsAuthenticated])
def cadastro_aluno(request):
    if request.method == 'GET':
        return render(request, 'usuarios/cadastro-aluno.html')
    if request.method == 'POST':
        nome = request.POST.get('nome')
        cpf = request.POST.get('cpf')
        if Aluno.objects.filter(cpf=cpf).exists():
            return render(request,'usuarios/cadastro-aluno.html',{'erro':'Aluno já matriculado!'})
        aluno = Aluno.objects.create(
            nome=nome,
            cpf=cpf,
        )
    return render(request, 'usuarios/cadastro-aluno.html', {"message": "Aluno cadastrado com sucesso!"})

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

@permission_classes([IsAuthenticated])
def detalhar_turma(request,id_turma):
    turma = get_object_or_404(Turma, id=id_turma)
    alunos = AlunoTurma.objects.filter(turma=turma)
    return render(request, 'usuarios/turma.html', {'turma': turma, 'alunos': alunos})

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def visualizar_usuarios(request):
    usuarios = User.objects.all()
    return render(request, 'usuarios/usuarios.html', {'usuarios':usuarios})

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def visualizar_turmas(request):
    turmas = Turma.objects.all()
    serializer = TurmaSerializer(turmas,many=True)
    return Response(serializer.data)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def visualizar_aluno_turmas(request):
    aluno_turmas = AlunoTurma.objects.all()
    serializer = AlunoTurmaSerializer(aluno_turmas,many=True)
    return Response(serializer.data)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def listar_turmas_do_aluno(request, aluno_id):
    try:
        aluno = Aluno.objects.get(id=aluno_id)
        turmas_matriculadas = aluno.aluno_turmas.all()
        turmas = [rel.turma for rel in turmas_matriculadas]
        serializer = TurmaSerializer(turmas, many=True)
        return Response(serializer.data)
    except Aluno.DoesNotExist:
        return Response({'error': 'Aluno não encontrado'}, status=404)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def cadastrar_turma(request):
    serializer = TurmaSerializer(data=request.data)
    if serializer.is_valid():
        turma = serializer.save()  # Salva a nova turma no banco
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@permission_classes([IsAuthenticated])
def visualizar_disciplinas(request):
    disciplinas = Disciplina.objects.all()
    paginator = Paginator(disciplinas, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    return render(request, 'usuarios/disciplinas.html', {'page_obj': page_obj})

@permission_classes([IsAuthenticated])
def visualizar_turmas(request):
    turmas = Turma.objects.all()
    paginator = Paginator(turmas, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    return render(request, 'usuarios/turmas.html', {'page_obj': page_obj})

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