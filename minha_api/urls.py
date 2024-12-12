from django.contrib import admin
from django.urls import path,include
from rest_framework_simplejwt.views import TokenObtainPairView,TokenRefreshView,TokenVerifyView
from rest_framework.routers import DefaultRouter
from rest_api.views import getUser,getUserDetail,AtualizarTurmaView,AlunoTurmaViewSet,AutenticarUser,getDisciplinas,CriarTurmaView,ProtectedView,TokenView,getAlunos,realizar_cadastro,CriarTurmaView
import rest_api.views as views

router = DefaultRouter()
router.register(r'/usuarios',getUser)
router.register(r'/disciplinas',getDisciplinas)
router.register(r'/alunos-matriculados',getAlunos)

urlpatterns = [
    path('',views.realizar_login),
    path('usuarios/cadastro.html',views.realizar_cadastro),
    path('usuarios/home.html',views.home),
    path('usuarios/usuarios.html',views.visualizar_usuarios,name='listar_usuarios'),
    path('usuarios/disciplinas.html',views.visualizar_disciplinas,name='listar_disciplinas'),
    path('usuarios/alunos.html',views.visualizar_alunos,name='listar_alunos'),
    path('usuarios/disciplina.html/<str:cod_disciplina>',views.detalhar_disciplina,name='detalhar_disciplina'),
    path('admin/', admin.site.urls),
    path('api',include(router.urls)),
    path('api/turmas',views.visualizar_turmas),
    path('api/cadastrar-turma',views.cadastrar_turma),
    path('api/aluno-turmas',AlunoTurmaViewSet.as_view({'get': 'list'})),
    path('api/aluno-turma/<str:disciplina>',AlunoTurmaViewSet.as_view({'get': 'retrieve'})),
    path('api/aluno/<int:aluno_id>/turmas', views.listar_turmas_do_aluno),
    path('disciplinas/<str:cod_disciplina>',views.get_by_cod),
    path('protectview',ProtectedView.as_view()),
    path('api-auth/',include('rest_framework.urls')),
    path('token',TokenObtainPairView.as_view()),
    path('token/atualizar',TokenRefreshView.as_view()),
    path('info-usuario', getUserDetail.as_view(), name='info-usuario'),
    path('token/obter-token',TokenView.as_view()),
    path('token/obter-usuario',AutenticarUser.as_view())
]