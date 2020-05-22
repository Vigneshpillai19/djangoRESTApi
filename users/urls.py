from django.urls import path
from django.conf.urls import url
from . import views

urlpatterns = [
    url('/', views.index, name="index"),
    path('signin', views.SigninView.as_view(), name="signin"),
    path('login', views.LoginView.as_view(), name="login"),
]