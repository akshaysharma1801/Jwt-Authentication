from django.contrib.auth import authenticate, get_user_model
from django.shortcuts import render
from django.db.models import Q
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import generics, permissions
from rest_framework_jwt.settings import api_settings
from rest_framework_jwt.authentication import JSONWebTokenAuthentication
from rest_framework.permissions import IsAuthenticated
from .serializers import UserRegisterSerializer

# Create your views here.
jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER
jwt_response_payload_handler = api_settings.JWT_RESPONSE_PAYLOAD_HANDLER

User = get_user_model()

class AuthView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **Kwargs):
        print(request.user)

        if request.user.is_authenticated:
            return Response ({'detail': 'you are already authenticated'})
        data = request.data
        username = data.get('username')
        password = data.get('password')
        
        UserModel = get_user_model()
        qs = UserModel.objects.filter(
            Q(email__iexact = username)|
            Q(username__iexact = username)
        ).distinct()
        print(qs)

        if qs.count() == 1:
            user_obj = qs.first()
            if user_obj.check_password(password):
                user = authenticate(username = user_obj.username, password = password)
                # user = user_obj
                payload = jwt_payload_handler(user)
                token = jwt_encode_handler(payload)
                response = jwt_response_payload_handler(token, user, request = request)
                return Response(response)
        return Response({'detail':'invalid credentials'})


class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserRegisterSerializer
    permission_classes = [permissions.AllowAny]

    def get_serializer_context(self, *args, **kwargs):
        return {"request" : self.request}


class Check(APIView):
    authentication_classes = (JSONWebTokenAuthentication,)
    permission_classes = (IsAuthenticated,) 

    def get(self, request):
        data = 'something'
        return Response(data)


# class RegisterView(APIView):
#     permission_classes = [permissions.AllowAny]

#     def post(self, request, *args, **Kwargs):

#         if request.user.is_authenticated:
#             return Response ({'detail': 'you are already registered'})
#         data = request.data
#         username = data.get('username')
#         email = data.get('username')
#         password = data.get('password')
#         password2 = data.get('password2')

#         UserModel = get_user_model()
#         qs = UserModel.objects.filter(
#             # Q(email__iexact = username)
#             Q(username__iexact = username)
#         )

#         if password != password2:
#             return Response ({'detail': 'password mismatch'})

#         if qs.exists():
#             return Response ({'detail':'User already exists'})
#         else:
#             user = UserModel.objects.create(username = username,email = email)
#             user.set_password(password)
#             user.save()
#             return Response({'detail':'please verify.'})
#         return Response({'detail':'invalid request'})
