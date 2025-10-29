# Auth Microservice (Go + gRPC)

Микросервис авторизации на Go с использованием gRPC. Реализует регистрацию, вход и проверку административных прав пользователя. Построен по принципам **чистой архитектуры**, включает кэширование через Redis, тесты (юнит + интеграционные) и контейнеризацию через Docker.

---

## Технологии

- **Go 1.21+**
- **gRPC**
- **Protocol Buffers**
- **PostgreSQL** — основное хранилище пользователей
- **Redis** — кэширование результата `IsAdmin`
- **Docker & Docker Compose**

---

## Архитектура

Проект следует **чистой архитектуре (Clean Architecture)**. Слои независимы: внешние зависимости (БД, кэш) легко заменяемы.

---

# Структура проекта `AuthService`

```
cmd/
└── auth/                   # Точка входа приложения
    └── main.go             # Запуск сервера
migrations/                 # Миграции
    └── main.go             # Точка входа для миграций
configs/                    # Конфигурации
    ├── local.go            # Загрузка .env и структуры Config
    └── ...
internal/                   # Внутренняя логика (не экспортируется)
  ├── app/                  # Структура приложения
  ├── config/               # Загрузка конфига
  ├── handlers/             # Обработчики (эндпоинты)
  ├── jwt/                  # Работа с JWT
  ├── models/               # Структуры данных
  ├── redis/                # Работа с Redis
  └── repository/
  │      ├── errors.go      # Ошибки репозитория
  │      ├── repository.go   # Интерфейсы
  │      └── database/      # Репозитории для работы с БД
  │           ├── app/      # AppRepository
  │           ├── mocks/    # Моки для тестов (mockgen)
  │           └── user/     # UserRepository (CRUD)
  │     
  │
  ├── server/
  │   └── server.go         # GRPC-сервер
  │
  └── service/              # Сервисы
         ├── errors.go      # Ошибки сервиса
         ├── service.go     # Интерфейсы
         └── auth/          # Сервис Auth
migrations/                 # Файлы миграций
pkg/
├── db/                     # Утилиты для подключения к PostgreSQL
│   └── db.go
├── logger/                 # Логгер
│   └── logger.go
tests/                      # Интеграционные тесты

```

---

## gRPC

| Метод       | Входные данные               | Ответ               | Описание |
|-------------|------------------------------|---------------------|---------|
| `Register`  | `email`, `password`          | `user_uuid`         | Регистрация пользователя |
| `Login`     | `email`, `password`, `app_id`| `token` (JWT)       | Аутентификация |
| `IsAdmin`   | `user_uuid`                  | `is_admin: bool`    | Проверка админ-прав (с кэшем) |

---

## Шаги по запуску
1. **Клонируй репозиторий и перейдите в папку**:
   ```
   git clone https://github.com/Estriper0/AuthService.git
   cd AuthService
   ```
2. Настройте переменные окружения в `.env`:
   ```env
   APP_ENV=local

   DB_HOST=localhost
   DB_PORT=5432
   DB_NAME=db_name
   DB_USER=postgres
   DB_PASSWORD=12345

   REDIS_ADDR=redis:6379
   ```

3. **Запусти с помощью Docker Compose**:
   ```
   docker compose up --build -d
   ```

---

## Тестирование

#### Все тесты
```bash
go test ./... -v
```

#### Только юнит-тесты
```bash
go test -short ./... -v
```

> Интеграционные тесты используют реальные PostgreSQL и Redis.
