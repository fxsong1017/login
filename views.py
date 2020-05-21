from django.shortcuts import render, redirect, HttpResponse
from django.views.generic import View
from login.models import UserInfo
from login.forms import UserForm, RegisterForm
import hashlib
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from itsdangerous import SignatureExpired
from django.conf import settings
from django.core.mail import send_mail
from celery_tasks.tasks import send_register_email
# Create your views here.
# def index(request):
#     return HttpResponse("hahahah")


def hash_code(s, salt='mysite'):
    h = hashlib.sha256()
    s += salt
    h.update(s.encode())
    return h.hexdigest()


class IndexView(View):
    def get(self, request):
        if not request.session.get('is_login', None):
            return redirect('/login')
        return render(request, 'login/index.html')


class LoginView(View):
    def get(self, request):
        #判断用户是否登陆
        if request.session.has_key('is_login'):
            return redirect('/index')
        #原生表单创建验证码
        # from captcha.models import CaptchaStore
        # from captcha.helpers import captcha_image_url
        # hashkey = CaptchaStore.generate_key()
        # imgage_url = captcha_image_url(hashkey)

        #表单创建验证码
        captcha_form = UserForm()
        return render(request, 'login/login.html', locals())

    def post(self, request):
        captcha_form = UserForm(request.POST)
        captcha_form.is_valid()
        if request.method == 'POST':
            username = request.POST.get('username')
            password = request.POST.get('password')
            if username.strip() and password:
                try:
                    user = UserInfo.objects.get(username=username)
                except:
                    message = '用户不存在！'
                    return render(request, 'login/login.html', {'message':message})
                if user.password == hash_code(password):
                    request.session['is_login'] = True
                    request.session['user_id'] = user.id
                    request.session['user_name'] = user.username
                    print(user.username)
                    return redirect('/index')
                else:
                    message = '密码不正确'
                    return render(request, 'login/login.html', {'message': message})
            else:
                message = "请检查填写的内容"
                return render(request, 'login/login.html', {'message': message})
        else:
            return render(request, 'login/login.html', locals())


class RegisterView(View):
    def get(self, request):
        if request.session.get('is_login',None):
            return redirect('/index')
        register_form = RegisterForm()
        return render(request, 'login/register.html', locals())

    def post(self, request):
        register_form = RegisterForm(request.POST)
        message = '请检查填写的内容'
        if register_form.is_valid():
            username = register_form.cleaned_data.get('username')
            password1 = register_form.cleaned_data.get('password1')
            password2 = register_form.cleaned_data.get('password2')
            email = register_form.cleaned_data.get('email')
            gender = register_form.cleaned_data.get('gender')

            if password1 != password2:
                massage = '两次密码不同！'
                return render(request, 'login/register.html', locals())

            else:
                same_name_user = UserInfo.objects.filter(username=username)
                if same_name_user:
                    message = '用户名已经存在！'
                    return render(request, 'login/register.html', locals())
                same_email_user = UserInfo.objects.filter(email=email)
                if same_email_user:
                    massage = '邮箱已注册'
                    return render(request, 'login/register.html', locals())

                new_user = UserInfo()
                new_user.username = username
                new_user.password = hash_code(password1)
                new_user.email = email
                new_user.gender = gender
                new_user.save()
                #发送激活邮件
                serializer = Serializer(settings.SECRET_KEY, 3600)
                info = {'confirm': new_user.id}
                token = serializer.dumps(info)  # bytes
                token = token.decode('utf8')
                #发邮件
                # subject = '欢迎注册信息'
                # msage = ''
                # sendr = settings.EMAIL_FROM
                # receiver = [email]
                # html_msage = '<h1>{},欢迎您注册成为我们的会员</h1>请点击下面链接激活您的账户</br><a herf="http://127.0.0.1:8000/active/{}">http://127.0.0.1:8000/active/{}</a>'.format(username, token, token)
                # send_mail(subject, msage, sendr, receiver, html_message=html_msage)

                # 使用celery异步发送邮件
                send_register_email.delay.delay(email, username, token)

                return redirect('/login')
        else:
            return render(request, 'login/register.html', locals())

class LogoutView(View):
    def get(self, request):
        if not request.session.get('is_login',None):
            #没有登陆，就不存在退出
            return redirect('/login')
        request.session.flush()
        return redirect('/login')


class ActiveView(View):
    """用户邮箱激活"""
    def get(self, request, token):
        serializer = Serializer(settings.SECRET_KEY, 3600)
        try:
            info = serializer.loads(token)
            user_id = info['confirm']
            user = UserInfo.objects.get(id=user_id)
            print(user)
            return redirect('/login')
        except SignatureExpired as e:
            #激活时间过期
            return HttpResponse("激活链接已过期")









