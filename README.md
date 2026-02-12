megra_police_http_server

Небольшой HTTP-сервер на C++ для Linux (armhf), который:

- Проверяет, запущен ли он от root (иначе завершает работу).
- Поднимает HTTP-сервер на порту `1616`.
- Обрабатывает запросы:
  - `GET /info` — возвращает текст `"Все ок"`.
  - `GET /log` — возвращает лог обработанных запросов.
  - `POST /upload` — принимает файл по `multipart/form-data` и сохраняет его в каталог `/tmp/`.

## Сборка

Требуется CMake и компилятор с поддержкой C++11.

```bash
mkdir build
cd build
cmake ..
cmake --build .
```

На выходе получится бинарник `megra_police_http_server`.

## Запуск

Сервер должен запускаться от root:

```bash
sudo ./megra_police_http_server
```

После запуска сервер слушает порт `1616` на всех интерфейсах (`0.0.0.0`).

## Примеры запросов

Проверка, что сервер жив:

```bash
curl http://IP_СЕРВЕРА:1616/info
```

Просмотр лога:

```bash
curl http://IP_СЕРВЕРА:1616/log
```

Загрузка файла в `/tmp/`:

```bash
curl -X POST -F "file=@myTestFile.txt" http://IP_СЕРВЕРА:1616/upload
```

или

```bash
wget --auth-no-challenge --no-check-certificate \
  --post-file=myTestFile.txt \
  http://IP_СЕРВЕРА:1616/upload
```

