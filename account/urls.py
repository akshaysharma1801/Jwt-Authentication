from django.urls import path
from rest_framework_jwt.views import obtain_jwt_token
from rest_framework_jwt.views import refresh_jwt_token
from rest_framework_jwt.views import verify_jwt_token
from account.views import AuthView,RegisterView,Check


app_name = 'account'
urlpatterns = [
    path('authview/', AuthView.as_view(),name="authview"),
    path('registerview/', RegisterView.as_view(),name="registerview"),
    path('check/', Check.as_view(),name="check"),
    path('jwt/', obtain_jwt_token),
    path('jwt-refresh/', refresh_jwt_token),
    path('jwt-verify/', verify_jwt_token),
]
