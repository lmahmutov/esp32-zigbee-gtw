# ESP32 Zigbee Gateway

Zigbee-шлюз на базе ESP32-S3 + ESP32-H2. Веб-интерфейс, REST API, WebSocket, OTA-обновления.

## Аппаратные требования

- **ESP32-S3** WROOM-1 (4MB flash, без PSRAM) — хост: WiFi, HTTP, WebSocket
- **ESP32-H2** — NCP (Network Co-Processor): ZBOSS-стек, координатор Zigbee
- Связь между чипами: UART (GPIO17 TX, GPIO18 RX), протокол ZNSP поверх SLIP

## Структура репозитория

```
├── gateway/         ESP32-S3 Gateway — основная прошивка
├── ncp/             ESP32-H2 NCP — Zigbee-координатор
├── web-flasher/     Веб-флешер (прошивка из браузера через USB)
├── docs/            Документация (API, протокол, параметры)
└── deploy.sh        Деплой прошивки на сервер
```

## Сборка

Требуется [ESP-IDF v5.3.2](https://docs.espressif.com/projects/esp-idf/en/v5.3.2/esp32s3/get-started/).

```bash
. $IDF_PATH/export.sh
```

### Gateway (ESP32-S3)

```bash
cd gateway
idf.py build
idf.py flash -p /dev/ttyUSB0
idf.py monitor -p /dev/ttyUSB0
```

### NCP (ESP32-H2)

```bash
cd ncp
idf.py set-target esp32h2   # только при первой сборке
idf.py build
idf.py flash -p /dev/ttyUSB1
```

## Веб-флешер

`web-flasher/index.html` — прошивка обоих чипов через USB из браузера (Chrome/Edge). Для работы нужен HTTP-сервер с файлами прошивки.

## Первый запуск

1. Прошить оба чипа (S3 и H2)
2. При первом включении шлюз создаёт точку доступа **ZigbeeGW-XXYY**
3. Подключиться к точке, пароль: `zigbee1234`
4. Открыть http://192.168.4.1
5. Указать SSID и пароль домашней WiFi
6. Шлюз перезагрузится и будет доступен по mDNS: `http://zigbee-gw.local`

## API

Подробная документация: [docs/README.md](docs/README.md)

Основные эндпоинты:
- `GET /api/status` — статус системы
- `GET /api/devices` — список Zigbee-устройств
- `POST /api/permit_join` — открыть сеть для подключения
- `POST /api/device/cmd` — команда устройству (on/off/toggle)
- `POST /api/ota` — OTA-обновление прошивки
- `ws://<ip>/ws` — WebSocket (реалтайм обновления)
