from django.contrib import admin
from django.urls import include, path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    # Legacy template paths used throughout the project
    path('usuarios/home.html', views.home, name='home_html'),
    path('usuarios/logout.html', views.realizar_logout, name='logout_html'),
    path('usuarios/usuarios.html', views.visualizar_usuarios, name='visualizar_usuarios'),
    path('usuarios/cadastro.html', views.realizar_cadastro, name='cadastro_usuario'),
    path('usuarios/alunos.html', views.visualizar_alunos, name='visualizar_alunos'),
    path('usuarios/disciplinas.html', views.visualizar_disciplinas, name='visualizar_disciplinas'),
    path('usuarios/turmas.html', views.visualizar_turmas, name='visualizar_turmas'),
    # Additional named routes expected by templates (aliases to existing views)
    path('usuarios/listar_usuarios/', views.visualizar_usuarios, name='listar_usuarios'),
    path('usuarios/listar_alunos/', views.visualizar_alunos, name='listar_alunos'),
    path('usuarios/cadastro_aluno/', views.cadastro_aluno, name='cadastro_aluno'),
    path('usuarios/criar_turma/', views.criar_turma, name='criar_turma'),
    path('usuarios/criar_disciplina/', views.cadastrar_disciplina, name='criar_disciplina'),
    path('usuarios/listar_disciplinas/', views.visualizar_disciplinas, name='listar_disciplinas'),
    path('usuarios/detalhar_disciplina/<str:cod_disciplina>/', views.detalhar_disciplina, name='detalhar_disciplina'),
    path('usuarios/editar_disciplina/<str:cod_disciplina>/', views.editar_disciplina, name='editar_disciplina'),
    path('usuarios/deletar_disciplina/<str:cod_disciplina>/', views.deletar_disciplina, name='deletar_disciplina'),
    path('usuarios/listar_turmas/', views.visualizar_turmas, name='listar_turmas'),
    path('usuarios/detalhar_aluno_in_turma/<int:id_turma>/', views.detalhar_turma, name='detalhar_aluno_in_turma'),
    path('usuarios/editar_turma/<int:turma_id>/', views.editar_turma, name='editar_turma'),
    path('usuarios/listar_notas_turma/<int:turma_id>/', views.listar_notas_turma, name='listar_notas_turma'),
    path('usuarios/deletar_turma/<int:turma_id>/', views.deletar_turma, name='deletar_turma'),
    path('usuarios/historico_aluno/<int:aluno_id>/', views.historico_aluno, name='historico_aluno'),
    path('usuarios/modificar_turma/<str:cod_disciplina>/<str:semestre>/', views.modificar_turma, name='modificar_turma'),
    path('admin/', admin.site.urls),
    path('login', views.realizar_login),
]