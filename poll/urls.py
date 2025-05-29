from django.urls import path
from django.contrib import admin
from . import views
from .views import CustomLoginView

urlpatterns = [
    path('', views.home, name='home'),
    path('signup/', views.signup, name='signup'),
    path('vote/', views.vote, name='vote'),
    path('create/<int:pk>', views.create, name='create'),
    path('seal', views.seal, name='seal'),
    path('verify', views.verify, name='verify'),
    path('results', views.result, name='result'),
    path('login/', CustomLoginView.as_view(), name='login'),
    path('logout/', views.logout_user, name='logout'),
]