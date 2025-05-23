from django.urls import path,include
import rest_api.views as views

urlpatterns = [
    path('',views.realizar_login),
    path('usuarios/logout.html', views.realizar_logout, name='logout'),
    path('login-error.html', views.login_error, name='login-error'),
    path('usuarios/cadastro.html',views.realizar_cadastro,name='cadastro_usuario'),
    path('usuarios/home.html',views.home),
    path('usuarios/cadastro-aluno.html',views.cadastro_aluno,name='cadastro_aluno'),
    path('usuarios/cadastrar-disciplina.html',views.cadastrar_disciplina,name='criar_disciplina'),
    path('usuarios/usuarios.html',views.visualizar_usuarios,name='listar_usuarios'),
    path('usuarios/disciplinas.html',views.visualizar_disciplinas,name='listar_disciplinas'),
    path('usuarios/alunos.html',views.visualizar_alunos,name='listar_alunos'),
    path('usuarios/turmas.html',views.visualizar_turmas,name='listar_turmas'),
    path('usuarios/turma.html/<int:id_turma>',views.detalhar_turma,name='detalhar_aluno_in_turma'),
    path('usuarios/criar-turma.html',views.criar_turma,name='criar_turma'),
    path('usuarios/modificar-turma.html/<str:cod_disciplina>/<str:semestre>',views.modificar_turma,name='modificar_turma'),
    path('usuarios/disciplina.html/<str:cod_disciplina>',views.detalhar_disciplina,name='detalhar_disciplina'),
    path('notas/turma/<int:turma_id>/', views.listar_notas_turma, name='listar_notas_turma'),
    path('historico/<int:aluno_id>/', views.historico_aluno, name='historico_aluno'),
]