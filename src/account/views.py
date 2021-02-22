from django.shortcuts import render, redirect
from django.views.generic import View
# from pprint import pprint
from django.contrib import messages
# Create your views here.
from validate_email import validate_email
from django.contrib.auth.models import User
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import force_bytes, force_text, DjangoUnicodeDecodeError
from .tokens import generate_token
from django.core.mail import EmailMessage
from django.conf import settings
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.tokens import PasswordResetTokenGenerator

import threading


class EmailThread(threading.Thread):
    def __init__(self, email_message):
        self.email_message = email_message
        threading.Thread.__init__(self)

    def run(self):
        self.email_message.send()


class RegistrationView(View):
    def get(self, request, *args, **kwargs):
        # pprint(dir(request.META))
        return render(request, 'account/register.html')

    def post(self, request, *args, **kwargs):
        # print(request.POST)
        # pprint(dir(request.POST))
        context = {
            'data': request.POST,
            'has_error': False
        }
        email = request.POST.get('email')
        name = request.POST.get('name')
        username = request.POST.get('username')
        password1 = request.POST.get('password1')
        password2 = request.POST.get('password2')

        if len(password1) < 6:
            messages.add_message(request, messages.ERROR, "Password should be at least 6 charecters")
            context['has_error'] = True

        if password1 != password2:
            messages.add_message(request, messages.ERROR, "Passwords doesn't match")
            context['has_error'] = True

        import re
        regex = '^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$'
        pattern = re.compile(regex)
        if not re.match(pattern, email):
            messages.add_message(request, messages.ERROR, "Please Enter a valid email address")
            context['has_error'] = True

        if User.objects.filter(email=email).exists():
            messages.add_message(request, messages.ERROR, "Email already Taken")
            context['has_error'] = True

        if User.objects.filter(username=username).exists():
            messages.add_message(request, messages.ERROR, "Username already Taken")
            context['has_error'] = True

        if context['has_error']:
            return render(request, 'account/register.html', context=context, status=400)

        user = User.objects.create_user(username=username, email=email)
        user.set_password(password1)
        user.first_name = name
        user.is_active = False
        user.save()
        current_site = get_current_site(request)
        email_subject = 'Activate Your Account'
        message = render_to_string('account/activate.html', {
            'user': user,
            'domain': current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(user.pk)),
            'token': generate_token.make_token(user),
        })
        email_message = EmailMessage(
            email_subject,
            message,
            settings.EMAIL_HOST_USER,
            [email]

        )
        # email_message.send()
        EmailThread(email_message).start()

        messages.add_message(request, messages.SUCCESS,
                             "Account created successfully please activate it by verifying email")
        return redirect('login')


class LoginView(View):
    def get(self, request, *args, **kwargs):
        return render(request, 'account/login.html')

    def post(self, request, *args, **kwargs):
        context = {
            'data': request.POST,
            'has_error': False,
        }
        username = request.POST.get('username')
        password = request.POST.get('password')
        if username == '':
            messages.add_message(request, messages.ERROR, "Username cannot be empty")
            context['has_error'] = True
        if password == '':
            messages.add_message(request, messages.ERROR, "Password cannot be empty")
            context['has_error'] = True

        user = authenticate(request, username=username, password=password)
        if not user and not context['has_error']:
            messages.add_message(request, messages.ERROR, "Invalid Credentials")
            context['has_error'] = True

        if context['has_error']:
            return render(request, 'account/login.html', context=context, status=401)

        login(request, user)
        return redirect('home')


class ActivateAccountView(View):
    def get(self, request, uidb64, token):
        try:
            uid = force_text(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except(TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None
        if user is not None and generate_token.check_token(user, token):
            user.is_active = True
            user.save()
            messages.add_message(request, messages.SUCCESS, "Account Activated Successfully")
            return redirect('login')
        return render(request, 'account/activate_failed.html', status=401)


class HomeView(View):
    def get(self, request):
        return render(request, 'core/home.html')


class LogoutView(View):
    def post(self, request, *args, **kwargs):
        logout(request)
        messages.add_message(request, messages.SUCCESS, "LoggedOut Successfully")
        return redirect('login')


class RequestResetEmailView(View):
    def get(self, request, *args, **kwargs):
        return render(request, 'account/req-reset-email.html')

    def post(self, request, *args, **kwargs):
        email = request.POST['email']

        import re
        regex = '^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$'
        pattern = re.compile(regex)
        if not re.match(pattern, email):
            messages.add_message(request, messages.ERROR, "Please Enter a valid email address")
            return render(request, 'account/req-reset-email.html')
        user = User.objects.filter(email=email)
        print(user)
        if user.exists():
            current_site = get_current_site(request)
            email_subject = '[Reset Your Password]'
            message = render_to_string('account/reset-user-password.html', {

                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(user[0].pk)),
                'token': PasswordResetTokenGenerator().make_token(user[0]),
            })
            email_message = EmailMessage(
                email_subject,
                message,
                settings.EMAIL_HOST_USER,
                [email]

            )
            # email_message.send()
            EmailThread(email_message).start()

            messages.add_message(request, messages.SUCCESS,
                                 "We have sent you an email with instructions on how to reset password")
            return render(request, 'account/req-reset-email.html')
        else:
            messages.add_message(request, messages.ERROR,
                                 "The email which is given is not in db")
            return render(request, 'account/req-reset-email.html')


class SetNewPasswordView(View):
    def get(self, request, uidb64, token):
        context = {
            'uidb64': uidb64,
            'token': token,
        }
        try:
            user_id = force_text(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=user_id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                messages.warning(request, "Password reset link expired,get a new link")
                return render(request, 'account/req-reset-email.html')
        except DjangoUnicodeDecodeError as identifier:
            messages.error(request, "something went wrong")
            return render(request, 'account/set-new-password.html', context=context)
        return render(request, 'account/set-new-password.html', context)

    def post(self, request, uidb64, token):
        context = {
            'uidb64': uidb64,
            'token': token,
            'has_error': False,
        }
        password1 = request.POST.get('password1')
        password2 = request.POST.get('password2')

        if len(password1) < 6:
            messages.add_message(request, messages.ERROR, "Password should be at least 6 charecters")
            context['has_error'] = True

        if password1 != password2:
            messages.add_message(request, messages.ERROR, "Passwords doesn't match")
            context['has_error'] = True
        if context['has_error']:
            return render(request, 'account/set-new-password.html', context=context)
        try:
            user_id = force_text(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=user_id)
            user.set_password(password1)
            user.save()
            messages.success(request, "Updated password successfully,Now you can login with new password")
            return redirect('login')
        except DjangoUnicodeDecodeError as identifier:
            messages.error(request, "something went wrong")
            return render(request, 'account/set-new-password.html', context=context)
        return render(request, 'account/req-reset-email.html', context)
