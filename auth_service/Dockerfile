FROM python:3.12
WORKDIR /app

# Установка системных зависимостей (если необходимы)
RUN apt-get update && apt-get install -y build-essential

# Копирование файла зависимостей и установка зависимостей
COPY requirements.txt .
RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

# Копирование всего остального кода
COPY . .

# Запуск приложения
CMD ["python", "main.py"]
