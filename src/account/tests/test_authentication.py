from django.test import TestCase
from django.urls import reverse
from django.apps import apps
from account.apps import AccountConfig
from django.contrib.auth.models import User


# Create your tests here.
class BaseTest(TestCase):
    def setUp(self):
        self.register_url = reverse('register')
        self.login_url = reverse('login')
        self.user = {
            'email':'testuser@gmail.com',
            'username':'username',
            'password1':'password',
            'password2':'password',
            'name':'full name',
        }
        self.user_short_password = {
            'email':'testuser@gmail.com',
            'username':'username',
            'password1':'test',
            'password2':'test',
            'name':'full name',
        }
        self.user_unmatching_password = {
            'email':'testuser@gmail.com',
            'username':'username',
            'password1':'test',
            'password2':'testa',
            'name':'full name',
        }
        self.user_invalid_email = {
            'email':'testuser.com',
            'username':'username',
            'password1':'test',
            'password2':'test',
            'name':'full name',
        }
        
        
        return super().setUp()
class ReportsConfigTest(TestCase):
    def test_apps(self):
        self.assertEqual(AccountConfig.name, 'account')
        self.assertEqual(apps.get_app_config('account').name, 'account')
        
class RegisterTest(BaseTest):
    def test_can_view_page_correctly(self):
        response = self.client.get(self.register_url) 
        self.assertEqual(response.status_code,200)
        self.assertTemplateUsed(response,'account/register.html')
    
    def test_can_register_user(self):
        response = self.client.post(self.register_url,self.user,format='text/html')
        self.assertEqual(response.status_code,302)
       
    
    def test_cant_register_user_short_password(self):
        response = self.client.post(self.register_url,self.user_short_password,format='text/html')
        self.assertEqual(response.status_code,400)
    
    def test_cant_register_user_unmatching_password(self):
        response = self.client.post(self.register_url,self.user_unmatching_password,format='text/html')
        self.assertEqual(response.status_code,400)
    
    def test_cant_register_user_invalid_email(self):
        response = self.client.post(self.register_url,self.user_invalid_email,format='text/html')
        self.assertEqual(response.status_code,400)
        
    def test_cant_register_user_username_taken(self):
        self.client.post(self.register_url,self.user,format='text/html')
        response = self.client.post(self.register_url,self.user,format='text/html')
        self.assertEqual(response.status_code,400)

class LoginTest(BaseTest):
    def test_can_access_page(self):
        response = self.client.get(self.login_url)
        self.assertEqual(response.status_code,200)
        self.assertTemplateUsed(response,'account/login.html')
    
    # def test_login_success(self):
    #     self.client.post(self.register_url,self.user,format='text/html')
    #     user=User.objects.filter(email=self.user['email']).first()
    #     user.is_active=True
    #     user.save()
    #     response= self.client.post(self.login_url,self.user,format='text/html')
    #     self.assertEqual(response.status_code,302)
    # def test_login_success(self):
    #     self.client.post(self.register_url,self.user,format='text/html')
    #     user = User.objects.filter(email= self.user['email']).first()
    #     user.is_active = True
    #     user.save()
    #     response = self.client.post(self.login_url,self.user,format='text/html')
    #     self.assertEqual(response.status_code,302)

    def test_cant_login_with_unverified_email(self):
        self.client.post(self.register_url,self.user,format='text/html')
        
        response = self.client.post(self.login_url,self.user,format='text/html')
        self.assertEqual(response.status_code,401)

    def test_cant_login_with_no_username(self):
        
        response = self.client.post(self.login_url,{'password':'password','username':''},format='text/html')
        self.assertEqual(response.status_code,401)
    
    def test_cant_login_with_no_username(self):
        
        response = self.client.post(self.login_url,{'password':'','username':'username'},format='text/html')
        self.assertEqual(response.status_code,401)