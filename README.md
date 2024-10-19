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
- JWT (JSON Web Token)
- Flasgger
- Gunicorn (HTTP сервер для развертывания Flask-приложений)

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
- Gunicorn

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
- Язык программирования: Python 3.12
- Фреймворк: Flask (веб-фреймворк для разработки микросервисов)
- Базы данных: MongoDB (для хранения информации о пользователях и транзакциях)
- Кэширование и сессии: Redis
- Аутентификация и авторизация: JWT (JSON Web Token)
- Система обмена сообщениями: Kafka
- Инструменты мониторинга и управления Kafka: Kafdrop, Kafka Manager, AKHQ
- Документация API: Flasgger (генерация документации Swagger)
- Контейнеризация и оркестрация: Docker, Docker Compose, Kubernetes
- Сервер для деплоя: Gunicorn (HTTP сервер для развертывания Flask-приложений)
- Работа с формами: WTForms
- Безопасность и управление сессиями: Werkzeug
- Kafka-клиенты: confluent_kafka (для продюсера и потребителя Kafka)



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

### Планируется оптимизировать:

1. Обеспечение Персистентности Данных
Настройка постоянных томов (Volumes) для Docker контейнеров:

Создать и настроить Docker Volumes для хранения данных MongoDB, Redis и Kafka вне контейнеров.
Обновить docker-compose.yml или Kubernetes манифесты для монтирования этих томов в соответствующие сервисы.
Резервное копирование данных:

Настроить регулярное автоматическое резервное копирование баз данных (MongoDB, Redis, Kafka).
Использовать инструменты, такие как mongodump для MongoDB, redis-cli для Redis и встроенные средства Kafka для резервного копирования.
2. Высокая Доступность и Репликация Баз Данных
MongoDB:

Настроить Replica Set для обеспечения репликации данных и высокой доступности.
Обеспечить наличие как минимум трех реплик для предотвращения состояния "split-brain".
Redis:

Внедрить Redis Sentinel для мониторинга и автоматического переключения на резервные узлы при сбоях.
Рассмотреть настройку Redis Cluster для масштабирования и повышения отказоустойчивости.
Kafka:

Настроить репликацию топиков Kafka, чтобы данные сохранялись на нескольких брокерах.
Обеспечить репликацию ZooKeeper для устойчивости управления Kafka.
3. Мониторинг и Автоматическое Восстановление
Инструменты мониторинга:

Внедрить Prometheus и Grafana для мониторинга состояния сервисов и баз данных.
Настроить алерты для критических событий, таких как сбои сервисов или превышение пороговых значений нагрузки.
Логирование:

Настроить централизованное логирование с использованием ELK Stack (Elasticsearch, Logstash, Kibana) или Grafana Loki.
Обеспечить сохранение логов вне контейнеров для предотвращения их потери при перезапуске.
Автоматическое восстановление:

Использовать Docker Compose или Kubernetes для автоматического перезапуска упавших контейнеров.
Настроить политики перезапуска (Restart Policies) для обеспечения непрерывной работы сервисов.
4. Оптимизация Управления Kafka
Упрощение администрирования:

Рассмотреть использование управляемых сервисов Kafka (например, Confluent Cloud или Amazon MSK) для снижения нагрузки на управление инфраструктурой.
Автоматизация процессов:

Внедрить инструменты инфраструктуры как кода (Terraform, Ansible) для автоматизации развертывания и управления кластером Kafka.
Оптимизация конфигураций:

Разработать стандартизированные шаблоны конфигураций для топиков и брокеров Kafka.
Обновить документацию по настройке Kafka с рекомендациями по оптимальным параметрам.
5. Усиление Механизмов Безопасности
Механизмы обновления токенов:

Внедрить Refresh Tokens для обеспечения возможности обновления Access Tokens без повторной аутентификации.
Настроить хранение Refresh Tokens в безопасном месте (например, в базе данных или Redis) с возможностью их отзыва.
Управление сроком действия сессий:

Установить короткий срок действия Access Tokens (например, 15 минут) и более длительный срок для Refresh Tokens (например, 7 дней).
Реализовать API для автоматического обновления Access Tokens с использованием Refresh Tokens.
Дополнительные меры безопасности:

Внедрить защиту от CSRF и XSS атак.
Использовать HttpOnly и Secure cookies для хранения токенов на клиентской стороне.
Внедрить систему аудита и логирования аутентификаций и использования Refresh Tokens для обнаружения подозрительной активности.
6. Миграция на Kubernetes (по желанию)
Преимущества Kubernetes:

Улучшенное управление контейнерами, автоматическое масштабирование, высокодоступные развертывания и управление состоянием.
Шаги миграции:

Перенести текущие Docker Compose конфигурации в Kubernetes манифесты.
Использовать Helm Charts для управления сложными приложениями, такими как Kafka, MongoDB и Redis.
Настроить CI/CD пайплайны для автоматического развертывания и обновления микросервисов в Kubernetes.
7. Интеграция с CI/CD
Настройка автоматизации:

Использовать инструменты CI/CD, такие как Jenkins, GitLab CI, GitHub Actions, для автоматизации тестирования, сборки и развертывания.
Шаги интеграции:

Настроить пайплайны для автоматического запуска тестов при каждом коммите.
Автоматизировать процесс развертывания на тестовых и продакшен окружениях.
8. Оптимизация Контейнеризации
Использование легковесных образов:

Перейти на минималистичные базовые образы (например, Alpine) для уменьшения размера Docker-образов и повышения безопасности.
Многоэтапная сборка:

Внедрить многоэтапную сборку Docker-образов для разделения этапов сборки и выполнения, что повысит безопасность и снизит размер финальных образов.
9. Управление Секретами и Безопасность Инфраструктуры
Хранение секретов:

Использовать системы управления секретами, такие как HashiCorp Vault или Kubernetes Secrets, для безопасного хранения конфиденциальных данных (паролей, ключей API).
Сканирование образов:

Внедрить регулярное сканирование Docker-образов на наличие уязвимостей с использованием инструментов, таких как Clair или Trivy.
10. Обновление Документации и Обучение Команды
Документация:

Обновить документацию проекта с учетом всех внесенных изменений, включая архитектурные изменения, инструкции по развертыванию и использованию новых механизмов.
Обучение:

Провести тренинги и семинары для команды по новым технологиям и процессам, внедренным в проект.
Обеспечить доступ к обучающим материалам и документации для повышения квалификации команды.
11. Тестирование и Валидация Изменений
Тестирование миграций:

Провести тестовую миграцию данных для проверки корректности переноса и интеграции новых баз данных.
Тестирование отказоустойчивости:

Провести симуляцию сбоев (например, отключение узлов баз данных или брокеров Kafka) для проверки работоспособности механизмов репликации и автоматического переключения.
Пентесты и аудит безопасности:

Провести тестирование на проникновение для выявления и устранения уязвимостей.
Внедрить регулярные аудиты безопасности для поддержания высокого уровня защиты системы.
12. Постепенное Внедрение Изменений
Планирование этапов:

Внедрять изменения поэтапно, начиная с наиболее критичных компонентов, чтобы минимизировать риски и обеспечить стабильность системы.
Мониторинг после изменений:

Внимательно следить за работой системы после каждого этапа изменений, быстро реагируя на возможные проблемы.
Обратная связь и итерации:

Собрать обратную связь от пользователей и команды после внедрения изменений.
Вносить необходимые коррективы и улучшения на основе полученных данных.


