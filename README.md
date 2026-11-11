# RASP-Scanner — Security Test Runner для бизнес-логики REST API

Универсальный, **конфигурируемый** инструмент для автоматизации проверок безопасности
REST API по методологии **OWASP WSTG**. Сценарии атак описываются в YAML — чтобы
добавить новую проверку, **не нужно менять код**. Движок умеет многошаговые сценарии,
несколько пользователей/ролей, передачу данных из ответа в следующий запрос, мутацию
параметров и — главное — проверку **фактического состояния** бизнес-операции, а не
только HTTP-кода.

Эталонный стенд для демонстрации — [VAmPI](https://github.com/erev0s/VAmPI)
(намеренно уязвимый API). Из коробки идут 5 сценариев, каждый находит реальную
уязвимость VAmPI.

```
$ rasp-scanner run
  ✗ VULNERABLE   [critical] WSTG-ATHN-04   broken-auth-debug-leak — Утечка учёток через debug → вход под админом
  ✗ VULNERABLE   [high    ] WSTG-ATHZ-04   idor-books — IDOR — чтение чужой книги
  ✗ VULNERABLE   [critical] WSTG-BUSL-01   mass-assignment-admin — Mass Assignment — эскалация привилегий
  ✗ VULNERABLE   [critical] WSTG-ATHZ-03   privilege-escalation-delete — Самоназначенный админ удаляет чужой аккаунт
  ✗ VULNERABLE   [critical] WSTG-BUSL-06   workflow-bypass-password — Обход владения — захват аккаунта

Summary: 5 scenarios — 5 vulnerable, 0 secure, 0 error
Verdict: ✗ VULNERABLE
```

---

## 1. Почему свой инструмент, а не готовый

Перед реализацией рассмотрены существующие классы инструментов:

| Инструмент | Что делает | Почему не подходит как основа |
|---|---|---|
| **OWASP ZAP / Burp** | DAST-сканеры, активные правила | Отлично ищут *технические* дыры (XSS, SQLi), но «слепы» к **бизнес-логике**: не знают, что «B не должен читать книгу A». |
| **Postman / Newman** | Коллекции запросов + тесты на JS | Многошаговость есть, но проверки пишутся кодом (JS), нет модели «роль/вердикт/WSTG», слабая переиспользуемость под security. |
| **Schemathesis / Dredd** | Контрактное тестирование по OpenAPI | Проверяют соответствие схеме, а не нарушение прав доступа и состояния. |
| **Karate / Tavern** | YAML/Gherkin API-тесты | Ближе всего по духу (YAML-сценарии), но это общие функциональные фреймворки: нет понятий роль-атакующий, вердикта `VULNERABLE/SECURE`, привязки к WSTG, `secure_if`. |

**Вывод:** на рынке нет лёгкого инструмента, где *security*-сценарий для бизнес-логики
— это декларативный конфиг с ролями, вердиктом и проверкой фактического состояния.
Поэтому строим свой движок, а зрелые библиотеки переиспользуем как кирпичи
(HTTP, валидация, jsonpath).

## 2. Технологии и обоснование

| Технология | Зачем | Обоснование выбора |
|---|---|---|
| **Python 3.14** | язык | Богатая экосистема security/HTTP, читаемость, быстрый старт. |
| **Pydantic v2** | валидация YAML-сценариев | Схема сценария = код моделей. Опечатка (`sever1ty`, кривой `WSTG-ID`, лишнее поле) **падает при загрузке**, а не в середине атаки. Сильный аргумент на ревью. |
| **httpx** | HTTP-клиент | Современный, типизированный, единый API, таймауты, управление TLS. |
| **jsonpath-ng** | извлечение данных из ответов | Промышленный jsonpath для `save` и проверок `json:`. |
| **Typer** | CLI | Декларативный CLI с автодокументацией и типами. |
| **Jinja2** | HTML-отчёт | Отделяет шаблон отчёта от данных. |
| **pytest** | тесты | Движок покрыт юнит-тестами через поддельный HTTP-клиент (без сети) + интеграционные против живого VAmPI. |
| **uv** | пакеты/venv | Быстрый, воспроизводимый lock. |

## 3. Архитектура

Код построен по паттернам **cosmicpython** (*Architecture Patterns with Python*):
доменное ядро, порты и адаптеры, сервисный слой, repository, unit of work и
composition root. Зависимости направлены **внутрь**: домен ничего не знает про httpx,
файлы и Typer.

```
             ┌─────────────────────────────────────────────┐
  entrypoints│  CLI (Typer):  run / validate / list        │  ← ввод
             └───────────────────────┬─────────────────────┘
                                     │ вызывает
             ┌───────────────────────▼─────────────────────┐
  bootstrap  │  composition root: собирает адаптеры в порты │
             └───────────────────────┬─────────────────────┘
                                     │
   service   │  services (use cases) · ScenarioRunner ·      │  оркестрация
    layer    │  StepExecutor · AuthManager · UnitOfWork      │
             └───────┬───────────────────────────┬──────────┘
                     │ зависит от ПОРТОВ          │
             ┌───────▼─────────┐        ┌─────────▼──────────┐
   ports     │ HttpClient      │        │ ScenarioRepository │  абстракции (ABC)
             │ Reporter · Clock│        │ RunIdProvider      │
             └───────▲─────────┘        └─────────▲──────────┘
                     │ реализуют                  │
  adapters   │ HttpxClient · Json/Html/Console    │ YamlRepository ·
             │ Reporter · Uuid/SystemClock        │ ...
             └────────────────────────────────────┘
                     │ оперируют доменом
             ┌───────▼─────────────────────────────────────┐
   domain    │ Scenario/Step/Request/Expect (спек, Pydantic)│  ЧИСТОЕ ЯДРО
  (чистый)   │ Renderer · extraction · assertions · verdict │  (без I/O)
             │ Context · HttpRequest/Response · results     │
             └─────────────────────────────────────────────┘
```

**Жизненный цикл шага** (контракт движка): `render → auth → send → save → secure_if → expect`.

```
Step ─render(${…})→ HttpRequest ─[as: role]→ AuthManager(ленивый логин, токен)
     → HttpClient.send → HttpResponse ─save→ Context ─secure_if?→ [SECURE, стоп]
     → expect ─classify(type)→ StepOutcome(PASSED/SECURE/VULNERABLE/ERROR)
```

Почему именно так:
- **Порт `HttpClient`** — главный шов: движок тестируется на поддельном клиенте без
  сети, а в проде подставляется httpx. Один и тот же код гоняет и юнит-, и интеграционные тесты.
- **`Repository`** абстрагирует источник сценариев (сегодня каталог YAML, завтра БД/реестр).
- **`Unit of Work`** владеет жизненным циклом HTTP-сессии прогона (пул соединений) и гарантирует её закрытие.
- **Чистый домен** (Renderer, extraction, assertions, verdict — без I/O) тестируется мгновенно и переиспользуется.

Подробный разбор формата сценария — в **[`scenario-reference.yaml`](scenario-reference.yaml)**.

## 4. Формат сценария (пример)

Один файл = один сценарий = один вид уязвимости. Пример — IDOR на VAmPI:

```yaml
id: idor-books
name: IDOR — чтение чужой книги
severity: high
wstg: WSTG-ATHZ-04
tags: [authz, idor]

roles:                               # логин ленивый: роль входит при первом "as:"
  user_a: { username: ${env.USER_A_NAME}, password: ${env.USER_A_PASS} }
  user_b: { username: ${env.USER_B_NAME}, password: ${env.USER_B_PASS} }

vars:
  book:   book-${run_id}             # ${run_id} уникален на каждое выполнение
  secret: secret-${run_id}

steps:
  - name: A создаёт книгу
    type: setup                      # провал = ERROR (тест не смог начаться)
    as: user_a
    request: { method: POST, path: /books/v1, json: { book_title: ${book}, secret: ${secret} } }
    expect:  { status: 200 }

  - name: B читает книгу A
    type: attack                     # провал безопасного ожидания = VULNERABLE
    as: user_b                       # та же операция от чужого лица — суть IDOR
    request: { method: GET, path: /books/v1/${book} }
    expect:
      status: [401, 403, 404]        # безопасно: чужому должно быть отказано
      body_not_contains: ${secret}   # и чужого секрета в ответе быть не должно
```

Ключевые возможности формата:
- **`${…}`** — переменные (`vars`, `save`), `${env.NAME}`, `${run_id}`, вложенные пути `${admins.0.username}`; **сохранение типа** (`${admin}` → `true`, а не `"true"`).
- **`save`** — извлечение из ответа: короткой строкой-путём или поиском в списке (`from/where/get/all`).
- **`expect` / `secure_if`** — проверки `status`, `json` (jsonpath), `body_contains/not_contains`, `vars`.
- **`type: setup|attack`** — задаёт точку расхождения безопасного и уязвимого API.

## 5. Поставляемые сценарии (5 WSTG-кейсов)

| Сценарий | WSTG | Тема ТЗ | Что доказывает на VAmPI |
|---|---|---|---|
| `idor-books` | WSTG-ATHZ-04 | **IDOR/BOLA** | B читает книгу A вместе с чужим `secret`. |
| `workflow-bypass-password` | WSTG-BUSL-06 | **Workflow Bypass** + **Transaction State** | Смена пароля чужого юзера в обход проверки владения; факт — вход под жертвой навязанным паролем. |
| `mass-assignment-admin` | WSTG-BUSL-01 | **Business Data Manipulation** | `admin:true` при регистрации; факт проверяется по `/me`, а не по ответу регистрации. |
| `privilege-escalation-delete` | WSTG-ATHZ-03 | **Transaction State Validation** | Самоназначенный админ удаляет чужой аккаунт; факт — жертвы больше нет. |
| `broken-auth-debug-leak` | WSTG-ATHN-04 | **Auth Bypass** | `/_debug` отдаёт пароли → вход под админом. |

> *Replay Attack* из примеров ТЗ намеренно не вошёл: VAmPI не реализует защиту от
> повтора (нет nonce/идемпотентности), поэтому демонстрация была бы неинформативной.
> Формат легко расширяется на него для подходящего стенда.

## 6. Установка и запуск

```bash
# 1. Зависимости (uv создаст .venv и поставит пакет)
uv sync --group dev

# 2. Поднять стенд VAmPI (Docker)
./scripts/vampi.sh up                     # http://localhost:5001

# 3. Учётки для idor-books
export $(grep -v '^#' .env.example | xargs)

# 4. Запуск
uv run rasp-scanner run                                   # все сценарии
uv run rasp-scanner run --only idor-books                 # один
uv run rasp-scanner run --tags authz                      # по тегам
uv run rasp-scanner run --report-json reports/r.json \
                        --report-html reports/r.html      # отчёты
uv run rasp-scanner validate                              # проверить сценарии (без сети)
uv run rasp-scanner list                                  # список сценариев
```

Выбор стенда: `--target http://host:port`, либо `TARGET_URL`, либо `--config config.example.yaml`.

### Свой сайт, а не VAmPI

Сканер не прибит к VAmPI — меняется только `--config` (механика стенда), сценарии пишутся
под API цели. Поддержано «из коробки»:

- **Тело запроса любого типа** в шаге: `json`, `form` (urlencoded), `raw` (+ `content_type`,
  для XML/GraphQL/SOAP), `multipart` + `files`. См. `scenario-reference.yaml`.
- **Гибкая авторизация** в конфиге (`auth.type`): `login` (тело логина любого типа; токен из
  JSON-тела / заголовка / cookie / regex; опц. `session`-cookies), `static` (API-key/токен из
  env), `basic` (HTTP Basic из учётки роли), `none`; плюс опциональный **CSRF pre-flow**.
  Подстановка учётки — `inject` в заголовок/cookie/query. Полная схема с комментариями —
  в `config.example.yaml`.

Готовый пример под чужой стенд (OWASP Juice Shop) — `configs/juiceshop.yaml`:

```bash
docker run --rm -p 3000:3000 bkimminich/juice-shop
uv run rasp-scanner run -c configs/juiceshop.yaml -d scenarios/juiceshop
```

**Код возврата** (для CI): `--fail-on vulnerable` (по умолчанию) → `1` при находке,
`2` при ошибке; `--fail-on error` → падать только на ошибках; `--fail-on never` → всегда `0`.

## 7. Отчёты

- **Console** — краткая сводка с проваленными проверками (всегда в stdout).
- **JSON** (`--report-json`) — машиночитаемый: запросы/ответы, проверки, вердикт, WSTG, remediation. Секреты **редактируются** (`***redacted***`): пароли в телах/`saved`/текстах, значения cookie, чувствительные заголовки (`Authorization`, `Set-Cookie`).
- **HTML** (`--report-html`) — автономная страница (light/dark), карточки по вердикту, разворачиваемые шаги с запросом/ответом и чек-листом.

## 8. Тесты

```bash
uv run pytest                      # всё (юнит + интеграция, если VAmPI поднят)
uv run pytest -m "not integration" # только юнит, без сети
uv run pytest -m integration       # только против живого VAmPI
```

Движок покрыт юнит-тестами через **поддельный `HttpClient`** (сценарии гоняются целиком,
без сети), плюс интеграционные проверяют, что каждый сценарий реально находит уязвимость
VAmPI.

## 9. CI (GitHub Actions)

`.github/workflows/security-tests.yml` поднимает VAmPI как service-контейнер, ставит
зависимости через `uv`, прогоняет весь pytest, затем собирает JSON/HTML-отчёты и
публикует их как артефакты. На реальном (не учебном) API шаг скана ставят на
`--fail-on vulnerable`, и пайплайн падает при регрессии безопасности.

## 10. Структура проекта

```
src/rasp_scanner/
  domain/         # чистое ядро: scenario (спек), rendering, extraction,
                  #   assertions, context, verdict, results, http, enums, errors
  ports/          # абстракции: HttpClient, Repository, Reporter, Clock/RunId
  adapters/       # httpx, YAML-repository, reporters (json/html/console), providers
  service_layer/  # engine (StepExecutor/ScenarioRunner), auth, services, unit_of_work
  entrypoints/    # CLI (Typer)
  config.py       # конфиг раннера (target, auth, …)
  bootstrap.py    # composition root
scenarios/        # 5 YAML-сценариев
tests/            # unit/ (через fake HttpClient) + integration/ (VAmPI)
scenario-reference.yaml   # полный справочник формата
config.example.yaml       # пример конфига раннера
```

## 11. Ограничения и дальнейшее развитие

- Движок **линейный** (без `for_each` по списку) — для доказательства уязвимости хватает одного элемента (`${admins.0}`).
- Планы: параллельный прогон сценариев, экспорт в SARIF (вкладка Security на GitHub), импорт эндпоинтов из OpenAPI, плагин-проверки.
