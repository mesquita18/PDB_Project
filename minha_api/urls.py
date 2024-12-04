from django.contrib import admin
from django.urls import path,include
from rest_framework_simplejwt.views import TokenObtainPairView,TokenRefreshView,TokenVerifyView
from rest_framework.routers import DefaultRouter
from rest_api.views import getUser,getUserDetail,AutenticarUser,getDisciplinas,ProtectedView,TokenView,getAlunos
import rest_api.views as views

router = DefaultRouter()
router.register(r'/usuarios',getUser)
router.register(r'/disciplinas',getDisciplinas)
router.register(r'/alunos/view',getAlunos)

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api',include(router.urls)),
    path('disciplinas/<str:cod_disciplina>',views.get_by_cod),
    path('protectview',ProtectedView.as_view()),
    path('api-auth/',include('rest_framework.urls')),
    path('token',TokenObtainPairView.as_view()),
    path('token/atualizar',TokenRefreshView.as_view()),
    path('info-usuario', getUserDetail.as_view(), name='info-usuario'),
    path('token/obter-token',TokenView.as_view()),
    path('token/obter-usuario',AutenticarUser.as_view())
]

# path('',views.realizar_login,name='listar_usuario'),
# path('usuarios/disciplinas.html',views.visualizar_disciplinas,name='listar_disciplinas'),