from django.contrib import admin
from django.urls import path,include
from rest_framework_simplejwt.views import TokenObtainPairView,TokenRefreshView,TokenVerifyView
from rest_framework.routers import DefaultRouter
from rest_api.views import getUser,getUserDetail,AutenticarUser,getDisciplinas,ProtectedView,TokenView
import rest_api.views as views

router = DefaultRouter()
router.register(r'Usuarios',getUser)
router.register(r'Disciplinas',getDisciplinas)

urlpatterns = [
    # path('',include(router.urls)),
    path('',views.realizar_login,name='listar_usuario'),
    path('admin/', admin.site.urls),
    path('Disciplinas/<str:cod_disciplina>',views.get_by_cod),
    path('protectview',ProtectedView.as_view()),
    path('api-auth/',include('rest_framework.urls')),
    path('token',TokenObtainPairView.as_view()),
    path('token/atualizar',TokenRefreshView.as_view()),
    path('info-usuario', getUserDetail.as_view(), name='info-usuario'),
    path('token/obter-token',TokenView.as_view()),
    path('token/obter-usuario',AutenticarUser.as_view())
]