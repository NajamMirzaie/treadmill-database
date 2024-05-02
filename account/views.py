from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from account.serializers import UserRegistrationSerializer,UserLoginSerializer,UserProfileSerializer,UserChangePasswordSerializer,SendPasswordResetEmailSerializer,UserPasswordResetSerializer
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
from rest_framework.exceptions import MethodNotAllowed


def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

class UserRegistrationView(APIView):
  def post(self,request,format=None):
    serializer = UserRegistrationSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    user = serializer.save()
    token = get_tokens_for_user(user)
    return Response({'token':token,'msg':'Registration Success'},status=status.HTTP_201_CREATED)


class UserLoginView(APIView):
  def post(self, request, format=None):
    serializer = UserLoginSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    email = serializer.data.get('email')
    password = serializer.data.get('password')
    user = authenticate(email=email, password=password)
    if user is not None:
      token = get_tokens_for_user(user)
      return Response({'token':token,'msg':'Login Success'}, status=status.HTTP_200_OK)
    else:
      return Response({'errors':{'non_field_errors':['Email or Password is not Valid']}}, status=status.HTTP_404_NOT_FOUND)


class UserProfileView(APIView):
  permission_classes = [IsAuthenticated]
  def get(self, request, format=None):
    serializer = UserProfileSerializer(request.user)
    return Response(serializer.data, status=status.HTTP_200_OK)



from rest_framework.generics import UpdateAPIView

class UpdateUserProfileView(UpdateAPIView):
    serializer_class = UserProfileSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=True)

        if serializer.is_valid():
            # Handle profile image update if present in request data
            profile_image = request.data.get('profile_image')
            if profile_image:
                # Assign the new profile image
                instance.profile_image = profile_image

            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)





class UserChangePasswordView(APIView):

    def post(self, request, format=None):
        serializer = UserChangePasswordSerializer(data=request.data, context={'user': request.user})
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({'msg': 'Password changed successfully'}, status=status.HTTP_200_OK)

    def get(self, request, format=None):
        raise MethodNotAllowed('GET')



class SendPasswordResetEmailView(APIView):
  def post(self, request, format=None):
    serializer = SendPasswordResetEmailSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    return Response({'msg':'Password Reset link send. Please check your Email'}, status=status.HTTP_200_OK)

class UserPasswordResetView(APIView):
  def post(self, request, uid, token, format=None):
    serializer = UserPasswordResetSerializer(data=request.data, context={'uid':uid, 'token':token})
    serializer.is_valid(raise_exception=True)
    return Response({'msg':'Password Reset Successfully'}, status=status.HTTP_200_OK)




from .models import TreadmillData, User
from .serializers import WorkoutSerializer
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework.decorators import api_view

@api_view(['POST'])
def save_workout(request):
    """
    Saves workout data for the authenticated user.
    """

    # Access and validate authorization header
    auth_header = request.META.get('HTTP_AUTHORIZATION')
    if not auth_header:
        return Response({'error': 'Missing authorization header'}, status=status.HTTP_401_UNAUTHORIZED)

    try:
        prefix, token = auth_header.split()
        if prefix.lower() != 'bearer':
            return Response({'error': 'Invalid authorization format'}, status=status.HTTP_401_UNAUTHORIZED)
    except ValueError:
        return Response({'error': 'Invalid authorization header'}, status=status.HTTP_401_UNAUTHORIZED)

    try:
        decoded_token = AccessToken(token)
        user_id = decoded_token['user_id']
    except:
        return Response({'error': 'Invalid or expired token'}, status=status.HTTP_401_UNAUTHORIZED)

    # Retrieve user object
    try:
        user = User.objects.get(pk=user_id)
    except User.DoesNotExist:
        return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

    # Extract and validate workout data using serializer
    serializer = WorkoutSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    # Save workout data
    serializer.save(user=user)  # User object already retrieved

    return Response(status=status.HTTP_201_CREATED)



from rest_framework.decorators import api_view
from rest_framework.response import Response
from .models import TreadmillData
from .serializers import WorkoutSerializer

@api_view(['GET'])
def get_all_workouts(request):
    # Assuming each workout has a field 'user' which is a foreign key to the user model
    user = request.user

    # Filter workouts for the authenticated user and order by timestamp in descending order
    treadmill_data = TreadmillData.objects.filter(user=user).order_by('-timestamp')

    serializer = WorkoutSerializer(treadmill_data, many=True)
    return Response(serializer.data)




