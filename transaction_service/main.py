import os
import json
import threading
from functools import wraps
from flask import Flask, request, Response, render_template, redirect, url_for, flash, session
import pymongo
import jwt
import logging
import redis
from confluent_kafka import Producer, Consumer, KafkaException, KafkaError
from flasgger import Swagger, swag_from
from flask_wtf import FlaskForm
from wtforms import IntegerField, StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
import requests

from flask_session import Session

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default_secret_key')
app.config['JSON_AS_ASCII'] = False

# Инициализация Flasgger
swagger = Swagger(app)

# Настройка сессий через Redis
app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_REDIS'] = redis.StrictRedis(host='redis', port=6379, db=0)
app.config['SESSION_COOKIE_NAME'] = 'fintech_session'
app.config['SESSION_COOKIE_PATH'] = '/'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = False  # True для HTTPS в продакшене
Session(app)

# Настройка подключения к MongoDB
try:
    mongo_client = pymongo.MongoClient("mongodb://mongo:27017/", serverSelectionTimeoutMS=5000)
    mongo_client.admin.command('ping')
    db = mongo_client["fintech_app"]
    transactions_collection = db["transactions"]
    logger.info("Подключение к MongoDB успешно установлено.")
except pymongo.errors.ServerSelectionTimeoutError as err:
    logger.error(f"Не удалось подключиться к MongoDB: {err}")
    raise

# Настройка Kafka Producer
producer_conf = {'bootstrap.servers': 'kafka:9092'}
producer = Producer(producer_conf)
logger.info("Kafka Producer инициализирован.")

# Декоратор для проверки JWT токена
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = session.get('token')
        if not token:
            response = json.dumps({'message': 'Токен отсутствует!'}, ensure_ascii=False)
            return Response(response, status=401, mimetype='application/json; charset=utf-8')

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = data['username']
        except jwt.ExpiredSignatureError:
            response = json.dumps({'message': 'Срок действия токена истёк!'}, ensure_ascii=False)
            return Response(response, status=401, mimetype='application/json; charset=utf-8')
        except jwt.InvalidTokenError:
            response = json.dumps({'message': 'Недействительный токен!'}, ensure_ascii=False)
            return Response(response, status=401, mimetype='application/json; charset=utf-8')

        return f(current_user, *args, **kwargs)

    return decorated

# Определение формы для веб-интерфейса
class TransactionForm(FlaskForm):
    amount = IntegerField('Amount', validators=[DataRequired()])
    description = StringField('Description')
    submit = SubmitField('Send Transaction')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# Маршрут для отображения формы логина через веб-интерфейс
@app.route('/transaction/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        data = {
            "username": form.username.data,
            "password": form.password.data
        }
        # Отправляем запрос на auth_service для логина
        try:
            response = requests.post('http://auth_service:5000/auth/login', json=data)
            if response.status_code == 200:
                token = response.json().get('token')
                session['token'] = token
                logger.info(f"Токен сохранён в сессии: {token}")
                flash("Вход выполнен успешно.", "success")
                return redirect(url_for('send_transaction'))
            else:
                error_message = response.json().get('message') or response.json().get('error')
                flash(f"Ошибка при входе: {error_message}", "danger")
        except Exception as e:
            flash(f"Ошибка при соединении с auth_service: {e}", "danger")
    return render_template('login_transaction_form.html', form=form)

# Временный маршрут для проверки сессии
@app.route('/session')
def check_session():
    token = session.get('token')
    return f"Токен в сессии: {token}"

# Маршрут для отображения формы и отправки транзакции через веб-интерфейс
@app.route('/send', methods=['GET', 'POST'])
@token_required
def send_transaction(current_user):
    form = TransactionForm()
    if form.validate_on_submit():
        transaction = {
            "user_id": current_user,
            "amount": form.amount.data,
            "description": form.description.data
        }
        # Отправляем транзакцию в Kafka напрямую
        try:
            producer.produce('transactions', value=json.dumps(transaction).encode('utf-8'), callback=delivery_callback)
            producer.poll(0)  # Обработка callback
            producer.flush()
            logger.info(f"Транзакция отправлена в Kafka: {transaction}")
            flash("Транзакция успешно отправлена!", "success")
        except Exception as e:
            logger.error(f"Ошибка при отправке транзакции: {e}")
            flash(f"Ошибка при отправке транзакции: {e}", "danger")
    return render_template('send_transaction.html', form=form)

# Маршрут для создания транзакции через API с документацией Swagger
@app.route('/transaction', methods=['POST'])
@token_required
@swag_from({
    'tags': ['Transactions'],
    'parameters': [
        {
            'name': 'body',
            'in': 'body',
            'required': True,
            'schema': {
                'type': 'object',
                'properties': {
                    'amount': {
                        'type': 'integer',
                        'example': 500000
                    },
                    'description': {
                        'type': 'string',
                        'example': 'Тестовая транзакция'
                    }
                },
                'required': ['amount']
            }
        }
    ],
    'responses': {
        201: {
            'description': 'Транзакция успешно отправлена',
            'schema': {
                'type': 'object',
                'properties': {
                    'message': {
                        'type': 'string',
                        'example': 'Транзакция отправлена в Kafka'
                    }
                }
            }
        },
        500: {
            'description': 'Ошибка при отправке транзакции',
            'schema': {
                'type': 'object',
                'properties': {
                    'message': {
                        'type': 'string',
                        'example': 'Ошибка при отправке в Kafka: ...'
                    }
                }
            }
        }
    }
})
def create_transaction(current_user):
    """Создание новой транзакции
    ---
    """
    data = request.get_json()
    if 'amount' not in data:
        response = json.dumps({"message": "Сумма обязательна"}, ensure_ascii=False)
        return Response(response, status=400, mimetype='application/json; charset=utf-8')

    transaction = {
        "user_id": current_user,
        "amount": data['amount'],
        "description": data.get('description', '')
    }
    # Отправляем транзакцию в Kafka
    try:
        producer.produce('transactions', value=json.dumps(transaction).encode('utf-8'), callback=delivery_callback)
        producer.poll(0)  # Обработка callback
        producer.flush()
        logger.info(f"Транзакция отправлена в Kafka: {transaction}")
        response = json.dumps({"message": "Транзакция отправлена в Kafka"}, ensure_ascii=False)
        return Response(response, status=201, mimetype='application/json; charset=utf-8')
    except KafkaException as e:
        logger.error(f"Ошибка при отправке в Kafka: {e}")
        response = json.dumps({"message": f"Ошибка при отправке в Kafka: {e}"}, ensure_ascii=False)
        return Response(response, status=500, mimetype='application/json; charset=utf-8')

# Маршрут для получения транзакций пользователя через API
@app.route('/transactions', methods=['GET'])
@token_required
@swag_from({
    'tags': ['Transactions'],
    'responses': {
        200: {
            'description': 'Список транзакций пользователя',
            'schema': {
                'type': 'array',
                'items': {
                    'type': 'object',
                    'properties': {
                        'user_id': {'type': 'string', 'example': 'testuser'},
                        'amount': {'type': 'integer', 'example': 500000},
                        'description': {'type': 'string', 'example': 'Тестовая транзакция'}
                    }
                }
            }
        },
        500: {
            'description': 'Ошибка при получении транзакций',
            'schema': {
                'type': 'object',
                'properties': {
                    'message': {
                        'type': 'string',
                        'example': 'Ошибка при получении транзакций: ...'
                    }
                }
            }
        }
    }
})
def get_transactions(current_user):
    """Получение всех транзакций пользователя
    ---
    """
    try:
        transactions = list(transactions_collection.find({"user_id": current_user}))
        for txn in transactions:
            txn['_id'] = str(txn['_id'])
        response = json.dumps(transactions, ensure_ascii=False)
        logger.info(f"Получено {len(transactions)} транзакций для пользователя {current_user}.")
        return Response(response, status=200, mimetype='application/json; charset=utf-8')
    except Exception as e:
        logger.error(f"Ошибка при получении транзакций: {e}")
        response = json.dumps({"message": f"Ошибка при получении транзакций: {e}"}, ensure_ascii=False)
        return Response(response, status=500, mimetype='application/json; charset=utf-8')

def delivery_callback(err, msg):
    if err is not None:
        logger.error(f"Ошибка доставки сообщения: {err}")
    else:
        logger.info(f"Сообщение доставлено в {msg.topic()} [{msg.partition()}] @ {msg.offset()}")

# Функция для потребления транзакций из Kafka и сохранения их в MongoDB
def consume_transactions():
    consumer_conf = {
        'bootstrap.servers': 'kafka:9092',
        'group.id': 'transaction_group',
        'auto.offset.reset': 'earliest'
    }
    consumer = Consumer(consumer_conf)
    consumer.subscribe(['transactions'])
    logger.info("Потребитель Kafka подписался на топик 'transactions'.")

    try:
        while True:
            msg = consumer.poll(1.0)
            if msg is None:
                continue
            if msg.error():
                if msg.error().code() == KafkaError._PARTITION_EOF:
                    continue
                else:
                    logger.error(f"Ошибка потребителя: {msg.error()}")
                    continue
            transaction = json.loads(msg.value().decode('utf-8'))
            transactions_collection.insert_one(transaction)
            logger.info(f"Транзакция сохранена: {transaction}")
    except Exception as e:
        logger.error(f"Ошибка потребителя: {e}")
    finally:
        consumer.close()
        logger.info("Потребитель Kafka закрыт.")

# Инициализация потребителя Kafka при запуске приложения
def start_consumer():
    consumer_thread = threading.Thread(target=consume_transactions)
    consumer_thread.daemon = True
    consumer_thread.start()
    logger.info("Потребитель Kafka запущен в отдельном потоке.")

# Запуск потребителя при инициализации модуля
start_consumer()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)
