#!/bin/bash
set -e

# Функция ожидания сервиса
wait_for_service() {
  host=$1
  port=$2
  service_name=$3
  max_attempts=30
  attempt_num=1

  until nc -z "$host" "$port"; do
    if (( attempt_num > max_attempts )); then
      echo "Не удалось подключиться к $service_name на $host:$port после $max_attempts попыток."
      exit 1
    fi
    echo "Ожидание $service_name на $host:$port... Попытка $attempt_num/$max_attempts"
    sleep 5
    ((attempt_num++))
  done

  echo "$service_name доступен на $host:$port"
}

# Ожидание Kafka
wait_for_service "kafka" "9092" "Kafka"

# Ожидание Redis
wait_for_service "redis" "6379" "Redis"

# Ожидание MongoDB
wait_for_service "mongo" "27017" "MongoDB"

# Запуск приложения
exec "$@"
