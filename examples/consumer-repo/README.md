# Пример: подключение RASP-Scanner в своём репозитории

Так выглядит **репозиторий А** (твой проект), который на GitHub Actions сам гоняет
проверки по своим сценариям и отдаёт отчёт. Движок (**репо Б**, RASP-Scanner)
подключается одной строкой `uses:` — его код выполняется на раннере А, скан бьёт
по твоему таргету, отчёт становится артефактом А.

## Раскладка

```
your-app/
├── .github/workflows/security.yml   # дёргает action сканера
└── security/
    ├── config.yaml                  # механика входа (auth) под твой API
    └── scenarios/*.yaml             # твои сценарии под твой API
```

## Что заменить под себя

1. `<owner>/RASP-Scanner@v1` в `security.yml` — реальный путь к репозиторию сканера и тег.
2. Образ/URL мишени: `ghcr.io/your-org/your-app` или `vars.STAGING_URL`.
3. `security/config.yaml` — endpoint логина, путь к токену, способ inject под твоё приложение.
4. `security/scenarios/*.yaml` — пути и поля под твой API (шаблон — `example-bola.yaml`).
5. Секреты в **Settings → Secrets and variables → Actions** (`API_PASS`, `USER_B_EMAIL`, …);
   в сценарии/конфиге они доступны как `${env.ИМЯ}`.

## Два варианта мишени (оба в `security.yml`)

- **`scan-local`** — приложение поднимается прямо в джобе (`services:`), скан по `localhost`.
  Самодостаточно, ничего внешнего не нужно.
- **`scan-staging`** — скан уже развёрнутого stage/preview-URL через `target:`. Для тяжёлых
  приложений; запускать, например, после деплоя.

Оставь тот job, который подходит, второй удали.

## Входы action'а

| Вход | Назначение | Дефолт |
|---|---|---|
| `target` | Базовый URL мишени | — (иначе `TARGET_URL`/конфиг) |
| `scenarios-dir` | Каталог сценариев | `security/scenarios` |
| `config` | YAML-конфиг раннера | — (дефолты) |
| `only` / `tags` | Фильтр сценариев | — |
| `fail-on` | `vulnerable` \| `error` \| `never` | `vulnerable` |
| `report-dir` | Куда писать отчёты | `reports` |
| `upload-artifact` | Залить отчёт артефактом | `true` |

Отчёт: артефакт `security-report` (JSON + HTML) + краткая таблица в summary прогона.
При `fail-on: vulnerable` находка роняет джобу (красный крестик) и блокирует merge.
