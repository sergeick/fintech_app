# Транзакции
FROM python:3.12
WORKDIR /app

# Установка системных зависимостей для confluent-kafka и netcat-openbsd
RUN apt-get update && apt-get install -y build-essential librdkafka-dev netcat-openbsd

# Копирование файла зависимостей и установка зависимостей
COPY requirements.txt .
RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

# Копирование всего остального кода
COPY . .

# Копирование скрипта ожидания и предоставление прав на выполнение
COPY wait_for_services.sh .
RUN chmod +x wait_for_services.sh

# Используем скрипт ожидания перед запуском приложения с gunicorn
CMD ["./wait_for_services.sh", "gunicorn", "--bind", "0.0.0.0:5001", "main:app", "--workers", "1", "--threads", "4"]
