# Import necessary Modules
from rest_framework.views import APIView, Response
from django.db import connection

from jose import jws
from rest_framework import status,exceptions

from passlib.context import CryptContext


# Start Code here
password_context = CryptContext(schemes=['bcrypt'], deprecated="auto")

# For Creating Password Hash
def get_password_hash(password):
    return password_context.hash(password)

# For verifying Password Hash
def verify_password(plain_password, hash_password):
    return password_context.verify(plain_password, hash_password)


def index(request):
    return HttpResponse("Welcome to Project...")

# Creating Token for API Request
def create_token(dict_data):
    token = jws.sign(dict_data, 'MY_SECRET_KEY', algorithm='HS256')
    return token

# Decoding the Received token to verify the user
def decode_token(token):
    data = jws.decode(token, 'MY_SECRET_KEY', algorithm='HS256')
    return data


# SignIn or Registration for New User
class SigninView(APIView):
    def get(self, request, format=None):
        return Response({"detail": "'GET' method not allowed for SignIn..."}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
    
    def post(self, request, format=None):
        data = request.data
        email = data['email']
        password = data['password']
        hashed_password = get_password_hash(password)
        # Write query for registering the user and create an entry in the database and store the hashed password in the database
        # query = "Write query according to the database you are using"
        query = "INSERT into users(email_id, password) values ('{}','{}')".format(email, hashed_password)
        try:
            with connection.cursor() as cursor:
                cursor.execute(query)
            encoded_token = create_token({ 'user_name': email, 'password': hashed_password })
            return Response({ 'token': encoded_token, 'detail': 'Request Success...' })
        except:
            return Response({ 'token': None, 'detail': 'Request Failed...' })

# LogIn for Registered User
class LoginView(APIView):
    def get(self, request, format=None):
        return Response({'detail': "'GET' method not allowed for LogIn..."}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
    
    def post(self, request, format=None):
        data = request.data
        email = data['email']
        password = data['password']
        # Fetch user details from the database using the email-id or username provided
        # query = "write query according to the database you are using"
        
        query = "SELECT * from users where email_id = '{}'".format(email)
        try:
            with connection.cursor() as cursor:
                cursor.execute(query)
                columns = [col[0] for col in cursor.description]
                res = dict(zip(columns, cursor.fetchone()))
        except:
            return Response({ 'detail': 'Something Wrong happened...' })

        # After fetching the details verify the user by using the password entered by the user and hashed password stored in the database
        match = verify_password(password, res['password'])
        if match:
            encoded_token = create_token({ 'username': res['email_id'], password: res['password'] })
            return Response({ 'token': encoded_token })
        else:
            msg = {
                "Authentication": 'Failed',
                "message": "Not a user"
            }
            raise exceptions.AuthenticationFailed(msg)
