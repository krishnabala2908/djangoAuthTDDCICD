# from django.contrib import admin
from django.urls import path
from .views import home
# from django.contrib.auth.decorators import login_required

urlpatterns = [

    path('', home, name='home')
]
