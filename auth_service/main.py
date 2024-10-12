# import os
# from flask import Flask, request, jsonify, Response
# from werkzeug.security import generate_password_hash, check_password_hash
# import redis
# import pymongo
# import jwt
# import datetime
# from functools import wraps
# import json  # Добавлен импорт json для использования json.dumps
#
# # Инициализация Flask
# app = Flask(__name__)
# app.config['JSON_AS_ASCII'] = False
#
# # Секретный ключ для подписи JWT токенов
# app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default_secret_key')
#
# # Настройка подключения к Redis для хранения сессий (если требуется)
# redis_client = redis.StrictRedis(host='redis', port=6379, db=0)
#
# # Настройка подключения к MongoDB для хранения данных о пользователях
# mongo_client = pymongo.MongoClient("mongodb://mongo:27017/")
# db = mongo_client["fintech_app"]
# users_collection = db["users"]
#
# # Декоратор для проверки JWT токена
# def token_required(f):
#     @wraps(f)
#     def decorated(*args, **kwargs):
#         token = None
#
#         # JWT передаётся в заголовке Authorization
#         if 'Authorization' in request.headers:
#             auth_header = request.headers['Authorization']
#             if auth_header.startswith('Bearer '):
#                 token = auth_header.split(" ")[1]
#
#         if not token:
#             response = json.dumps({'message': 'Токен отсутствует!'}, ensure_ascii=False)
#             return Response(response, status=401, mimetype='application/json; charset=utf-8')
#
#         try:
#             data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
#             current_user = users_collection.find_one({'username': data['username']})
#             if not current_user:
#                 response = json.dumps({'message': 'Пользователь не найден!'}, ensure_ascii=False)
#                 return Response(response, status=401, mimetype='application/json; charset=utf-8')
#         except jwt.ExpiredSignatureError:
#             response = json.dumps({'message': 'Срок действия токена истёк!'}, ensure_ascii=False)
#             return Response(response, status=401, mimetype='application/json; charset=utf-8')
#         except jwt.InvalidTokenError:
#             response = json.dumps({'message': 'Недействительный токен!'}, ensure_ascii=False)
#             return Response(response, status=401, mimetype='application/json; charset=utf-8')
#
#         # Добавляем текущего пользователя в аргументы функции
#         return f(current_user, *args, **kwargs)
#
#     return decorated
#
# # Маршрут для регистрации пользователя
# @app.route('/auth/signup', methods=['POST'])
# def signup():
#     data = request.get_json()
#     if 'username' not in data or 'password' not in data:
#         response = json.dumps({"error": "Требуются имя пользователя и пароль"}, ensure_ascii=False)
#         return Response(response, status=400, mimetype='application/json; charset=utf-8')
#
#     # Проверяем, существует ли пользователь с таким же именем
#     if users_collection.find_one({"username": data['username']}):
#         response = json.dumps({"error": "Имя пользователя уже занято"}, ensure_ascii=False)
#         return Response(response, status=400, mimetype='application/json; charset=utf-8')
#
#     # Хеширование пароля для безопасности
#     hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
#
#     # Создание пользователя
#     user = {
#         "username": data['username'],
#         "password": hashed_password
#     }
#
#     # Добавление пользователя в MongoDB
#     users_collection.insert_one(user)
#
#     response = json.dumps({"message": "Пользователь успешно зарегистрирован"}, ensure_ascii=False)
#     return Response(response, status=201, mimetype='application/json; charset=utf-8')
#
# # Маршрут для логина пользователя
# @app.route('/auth/login', methods=['POST'])
# def login():
#     data = request.get_json()
#     if 'username' not in data or 'password' not in data:
#         response = json.dumps({"error": "Требуются имя пользователя и пароль"}, ensure_ascii=False)
#         return Response(response, status=400, mimetype='application/json; charset=utf-8')
#
#     user = users_collection.find_one({"username": data['username']})
#
#     # Проверка соответствия пароля
#     if user and check_password_hash(user['password'], data['password']):
#         # Генерация JWT токена
#         token = jwt.encode({
#             'username': user['username'],
#             'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
#         }, app.config['SECRET_KEY'], algorithm="HS256")
#
#         response_data = {"message": "Вход выполнен успешно", "token": token}
#         response = json.dumps(response_data, ensure_ascii=False)
#         return Response(response, status=200, mimetype='application/json; charset=utf-8')
#
#     response = json.dumps({"message": "Неверные учетные данные"}, ensure_ascii=False)
#     return Response(response, status=401, mimetype='application/json; charset=utf-8')
#
# # Защищённый маршрут для тестирования
# @app.route('/auth/protected', methods=['GET'])
# @token_required
# def protected_route(current_user):
#     message = f'Здравствуйте, {current_user["username"]}! Это защищённый маршрут.'
#     response = json.dumps({'message': message}, ensure_ascii=False)
#     return Response(response, status=200, mimetype='application/json; charset=utf-8')
#
# if __name__ == "__main__":
#     app.run(host="0.0.0.0", port=5000)


import os
from flask import Flask, request, jsonify, Response, render_template, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
import redis
import pymongo
import jwt
import datetime
from functools import wraps
import json  # Для использования json.dumps
from flasgger import Swagger, swag_from
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length

# Инициализация Flask
app = Flask(__name__)
app.config['JSON_AS_ASCII'] = False

# Секретный ключ для подписи JWT токенов
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default_secret_key')
app.config['WTF_CSRF_ENABLED'] = False  # Для упрощения примера

# Инициализация Flasgger
swagger = Swagger(app)

# Настройка подключения к Redis для хранения сессий (если требуется)
redis_client = redis.StrictRedis(host='redis', port=6379, db=0)

# Настройка подключения к MongoDB для хранения данных о пользователях
mongo_client = pymongo.MongoClient("mongodb://mongo:27017/")
db = mongo_client["fintech_app"]
users_collection = db["users"]

# Декоратор для проверки JWT токена
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        # JWT передаётся в заголовке Authorization
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(" ")[1]

        # Если токен не в заголовках, пытаемся получить его из сессии
        if not token:
            token = session.get('token')

        if not token:
            response = json.dumps({'message': 'Токен отсутствует!'}, ensure_ascii=False)
            return Response(response, status=401, mimetype='application/json; charset=utf-8')

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = users_collection.find_one({'username': data['username']})
            if not current_user:
                response = json.dumps({'message': 'Пользователь не найден!'}, ensure_ascii=False)
                return Response(response, status=401, mimetype='application/json; charset=utf-8')
        except jwt.ExpiredSignatureError:
            response = json.dumps({'message': 'Срок действия токена истёк!'}, ensure_ascii=False)
            return Response(response, status=401, mimetype='application/json; charset=utf-8')
        except jwt.InvalidTokenError:
            response = json.dumps({'message': 'Недействительный токен!'}, ensure_ascii=False)
            return Response(response, status=401, mimetype='application/json; charset=utf-8')

        # Добавляем текущего пользователя в аргументы функции
        return f(current_user, *args, **kwargs)

    return decorated

# Определение формы для веб-интерфейса регистрации и логина (опционально)
class SignupForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# Маршрут для регистрации пользователя через API с документацией Swagger
@app.route('/auth/signup', methods=['POST'])
@swag_from({
    'tags': ['Authentication'],
    'parameters': [
        {
            'name': 'body',
            'in': 'body',
            'required': True,
            'schema': {
                'type': 'object',
                'properties': {
                    'username': {
                        'type': 'string',
                        'example': 'testuser'
                    },
                    'password': {
                        'type': 'string',
                        'example': 'securepassword'
                    }
                },
                'required': ['username', 'password']
            }
        }
    ],
    'responses': {
        201: {
            'description': 'Пользователь успешно зарегистрирован',
            'schema': {
                'type': 'object',
                'properties': {
                    'message': {
                        'type': 'string',
                        'example': 'Пользователь успешно зарегистрирован'
                    }
                }
            }
        },
        400: {
            'description': 'Ошибка при регистрации пользователя',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {
                        'type': 'string',
                        'example': 'Имя пользователя уже занято'
                    }
                }
            }
        }
    }
})
def signup():
    """
    Регистрация нового пользователя
    ---
    """
    data = request.get_json()
    if 'username' not in data or 'password' not in data:
        response = json.dumps({"error": "Требуются имя пользователя и пароль"}, ensure_ascii=False)
        return Response(response, status=400, mimetype='application/json; charset=utf-8')

    # Проверяем, существует ли пользователь с таким же именем
    if users_collection.find_one({"username": data['username']}):
        response = json.dumps({"error": "Имя пользователя уже занято"}, ensure_ascii=False)
        return Response(response, status=400, mimetype='application/json; charset=utf-8')

    # Хеширование пароля для безопасности
    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')

    # Создание пользователя
    user = {
        "username": data['username'],
        "password": hashed_password
    }

    # Добавление пользователя в MongoDB
    users_collection.insert_one(user)

    response = json.dumps({"message": "Пользователь успешно зарегистрирован"}, ensure_ascii=False)
    return Response(response, status=201, mimetype='application/json; charset=utf-8')

# Маршрут для логина пользователя через API с документацией Swagger
@app.route('/auth/login', methods=['POST'])
@swag_from({
    'tags': ['Authentication'],
    'parameters': [
        {
            'name': 'body',
            'in': 'body',
            'required': True,
            'schema': {
                'type': 'object',
                'properties': {
                    'username': {
                        'type': 'string',
                        'example': 'testuser'
                    },
                    'password': {
                        'type': 'string',
                        'example': 'securepassword'
                    }
                },
                'required': ['username', 'password']
            }
        }
    ],
    'responses': {
        200: {
            'description': 'Успешный вход',
            'schema': {
                'type': 'object',
                'properties': {
                    'message': {
                        'type': 'string',
                        'example': 'Вход выполнен успешно'
                    },
                    'token': {
                        'type': 'string',
                        'example': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...'
                    }
                }
            }
        },
        400: {
            'description': 'Ошибка при входе',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {
                        'type': 'string',
                        'example': 'Требуются имя пользователя и пароль'
                    }
                }
            }
        },
        401: {
            'description': 'Неверные учетные данные',
            'schema': {
                'type': 'object',
                'properties': {
                    'message': {
                        'type': 'string',
                        'example': 'Неверные учетные данные'
                    }
                }
            }
        }
    }
})
def login():
    """
    Вход пользователя
    ---
    """
    data = request.get_json()
    if 'username' not in data or 'password' not in data:
        response = json.dumps({"error": "Требуются имя пользователя и пароль"}, ensure_ascii=False)
        return Response(response, status=400, mimetype='application/json; charset=utf-8')

    user = users_collection.find_one({"username": data['username']})

    # Проверка соответствия пароля
    if user and check_password_hash(user['password'], data['password']):
        # Генерация JWT токена
        token = jwt.encode({
            'username': user['username'],
            'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=30)
        }, app.config['SECRET_KEY'], algorithm="HS256")

        response_data = {"message": "Вход выполнен успешно", "token": token}
        response = json.dumps(response_data, ensure_ascii=False)

        # Сохраняем токен в сессии
        session['token'] = token

        return Response(response, status=200, mimetype='application/json; charset=utf-8')

    response = json.dumps({"message": "Неверные учетные данные"}, ensure_ascii=False)
    return Response(response, status=401, mimetype='application/json; charset=utf-8')

# Защищённый маршрут для тестирования через API с документацией Swagger
@app.route('/auth/protected', methods=['GET'])
@token_required
@swag_from({
    'tags': ['Authentication'],
    'responses': {
        200: {
            'description': 'Доступ к защищённому маршруту',
            'schema': {
                'type': 'object',
                'properties': {
                    'message': {
                        'type': 'string',
                        'example': 'Здравствуйте, testuser! Это защищённый маршрут.'
                    }
                }
            }
        },
        401: {
            'description': 'Ошибка авторизации',
            'schema': {
                'type': 'object',
                'properties': {
                    'message': {
                        'type': 'string',
                        'example': 'Токен отсутствует!'
                        }
                    }
                }
            }
        }
    })
def protected_route(current_user):
    """
    Доступ к защищённому маршруту
    ---
    """
    message = f'Здравствуйте, {current_user["username"]}! Это защищённый маршрут.'
    response = json.dumps({'message': message}, ensure_ascii=False)
    return Response(response, status=200, mimetype='application/json; charset=utf-8')

# Маршрут для отображения формы регистрации через веб-интерфейс (опционально)
@app.route('/auth/signup_form', methods=['GET', 'POST'])
def signup_form():
    form = SignupForm()
    if form.validate_on_submit():
        data = {
            "username": form.username.data,
            "password": form.password.data
        }
        # Повторяем логику из API signup
        if users_collection.find_one({"username": data['username']}):
            flash("Имя пользователя уже занято", "danger")
            return redirect(url_for('signup_form'))

        hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
        user = {
            "username": data['username'],
            "password": hashed_password
        }
        users_collection.insert_one(user)
        flash("Пользователь успешно зарегистрирован", "success")
        return redirect(url_for('signup_form'))
    return render_template('signup_form.html', form=form)

# Маршрут для отображения формы логина через веб-интерфейс (опционально)
@app.route('/auth/login_form', methods=['GET', 'POST'])
def login_form():
    form = LoginForm()
    if form.validate_on_submit():
        data = {
            "username": form.username.data,
            "password": form.password.data
        }
        user = users_collection.find_one({"username": data['username']})
        if user and check_password_hash(user['password'], data['password']):
            token = jwt.encode({
                'username': user['username'],
                'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=30)
            }, app.config['SECRET_KEY'], algorithm="HS256")
            session['token'] = token
            flash(f"Вход выполнен успешно. Ваш токен: {token}", "success")
            return redirect(url_for('login_form'))
        else:
            flash("Неверные учетные данные", "danger")
    return render_template('login_form.html', form=form)

# Защищённый маршрут для веб-интерфейса (опционально)
@app.route('/auth/protected_web', methods=['GET'])
@token_required
def protected_route_web(current_user):
    message = f'Здравствуйте, {current_user["username"]}! Это защищённый маршрут через веб-интерфейс.'
    flash(message, "info")
    return render_template('protected_web.html', message=message)




# Главная страница с меню
@app.route('/')
def index():
    return render_template('index.html')



if __name__ == "__main__":
    # Создайте папку templates и добавьте файлы signup_form.html, login_form.html и protected_web.html
    app.run(host="0.0.0.0", port=5000)
