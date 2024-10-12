![изображение](https://github.com/user-attachments/assets/f76bb90d-b703-41ee-8f49-eadb063600ab)

# Fintech App
### Обзор проекта
Fintech App — это система на базе микросервисов, предназначенная для управления аутентификацией пользователей и финансовыми транзакциями с использованием Kafka в качестве платформы для обмена сообщениями. Система состоит из нескольких сервисов, таких как auth_service для аутентификации пользователей и transaction_service для обработки и логирования транзакций пользователей. Сервисы взаимодействуют через Kafka, а для мониторинга и управления топиками Kafka используются такие инструменты, как Kafdrop, Kafka Manager и AKHQ.

### Структура проекта
Приложение разделено на два основных сервиса:
1. auth_service: Управляет регистрацией, входом в систему и аутентификацией пользователей.
2. transaction_service: Обрабатывает транзакции между пользователями и записывает их в Kafka.
Дополнительно, система включает инструменты для мониторинга Kafka, такие как Kafdrop, AKHQ и Kafka Manager.

### Docker и микросервисная архитектура
В данном проекте используются Docker-контейнеры для развертывания каждого сервиса отдельно. Это позволяет поддерживать изолированную среду для каждого микросервиса, упрощает масштабирование и обеспечивает легкое управление зависимостями. Каждый микросервис (auth_service, transaction_service и инструменты для работы с Kafka) разворачивается в своем Docker-контейнере с использованием Docker Compose, что значительно упрощает развертывание и управление всей системой.

### Компоненты Docker
- MongoDB: используется для хранения информации о пользователях и транзакциях.
- Redis: отвечает за управление сессиями.
- Zookeeper и Kafka: используются для организации очередей сообщений и управления топиками.
- auth_service: микросервис для управления регистрацией и аутентификацией пользователей.
- transaction_service: микросервис для обработки транзакций.
- Kafdrop, Kafka Manager, AKHQ: инструменты для мониторинга и управления Kafka.
  
### Как взаимодействуют контейнеры
1. auth_service работает с Redis для управления сессиями и с MongoDB для хранения данных о пользователях.
2. transaction_service работает с Kafka для публикации транзакций в топики и MongoDB для хранения информации о транзакциях.
3. Все сервисы связываются через Docker-сеть (app-network), что позволяет им легко взаимодействовать друг с другом без необходимости указывать IP-адреса.

### Запуск и управление Docker-контейнерами
Для запуска всех микросервисов и связанных с ними инструментов используется Docker Compose. Этот инструмент позволяет одновременно запускать все контейнеры с минимальными усилиями. Docker Compose управляет контейнерами, устанавливает зависимости между ними и следит за тем, чтобы все компоненты были запущены в правильном порядке.

### Команды для работы с Docker
1. Запуск всех сервисов: docker-compose up
2. Остановка сервисов: docker-compose down

### Порты для доступа к сервисам
- auth_service:
  http://localhost:5000
  
- transaction_service:
  http://localhost:5001
  
- Kafdrop:
  http://localhost:9000
  
- Kafka Manager:
  http://localhost:9001
  
- AKHQ:
  http://localhost:8080
  
- auth_service API:
  http://localhost:5000/apidocs
  
- transaction_service API:
  http://localhost:5001/apidocs
  
### Описание сервисов и компонентов
1. auth_service - Отвечает за аутентификацию и регистрацию пользователей.

Технологии:
- Flask
- MongoDB
- Redis
- JWT
- Flasgger

HTML-страницы: 
- login_form.html
- signup_form.html
- protected_web.html
- index.html

2. transaction_service - Обрабатывает транзакции пользователей и отправляет их в Kafka.

Технологии: 
- Flask
- MongoDB
- Kafka
- Redis
- Flasgger

HTML-страницы: 
- login_transaction_form.html
- send_transaction.html


4. Kafdrop - Веб-интерфейс для просмотра и мониторинга топиков Kafka. Порт: 9000
5. Kafka Manager - Инструмент управления для Kafka, предоставляет возможности для управления кластерами, топиками и конфигурацией Kafka. Порт: 9001
7. AKHQ - Веб-интерфейс для администрирования и мониторинга Kafka. Порт: 8080
   Конфигурация: Использует файл application.yml, который монтируется в контейнер AKHQ.
9. Flasgger (Swagger) - Flasgger используется для создания интерактивной документации API для всех микросервисов, обеспечивая удобный способ тестирования запросов. Порт:
- 5000 для auth_service
- 5001 для transaction_service


### Стек технологий и используемые библиотеки:

    Python 3.12 — основной язык программирования.
    Flask — веб-фреймворк для разработки микросервисов.
    MongoDB — NoSQL база данных для хранения данных о пользователях и транзакциях.
    Redis — система управления сессиями и кешем.
    JWT (JSON Web Token) — для генерации и проверки токенов аутентификации.
    Kafka — платформа обмена сообщениями для передачи данных о транзакциях.
    Kafdrop, Kafka Manager, AKHQ — инструменты для мониторинга и управления топиками Kafka.
    Flasgger — для создания интерактивной документации API (Swagger).
    Docker — контейнеризация микросервисов.
    Docker Compose — для управления многоконтейнерными приложениями.
    Werkzeug — библиотека для работы с паролями и безопасности.
    WTForms — для обработки HTML-форм на серверной стороне.

Компоненты Docker:

    MongoDB — для хранения данных о пользователях и транзакциях.
    Redis — для управления сессиями.
    Zookeeper и Kafka — для организации очередей сообщений.
    auth_service — микросервис для аутентификации пользователей.
    transaction_service — микросервис для обработки транзакций.
    Kafdrop, Kafka Manager, AKHQ — для мониторинга и управления Kafka.



===

### Планируется интегрировать:
- Сервис уведомлений:
        Отвечает за отправку уведомлений пользователям (например, при успешной транзакции).
        Kafka используется для передачи данных уведомлений.
        Обработка осуществляется через Flask.

- Сервис аналитики:
        Обрабатывает и анализирует большие объемы данных с использованием Dask и Pandas.
        Предоставляет отчеты и статистику по транзакциям.
        Используем Prometheus для мониторинга и Grafana для визуализации метрик.

- Сервис мониторинга:
        С помощью Prometheus собирает метрики, а Grafana визуализирует их.
        Мониторинг производительности всех микросервисов.


