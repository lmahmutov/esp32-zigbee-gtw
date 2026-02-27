# ESP32 Zigbee Gateway — Документация

Аппаратная платформа: ESP32-S3 WROOM-1 (4MB flash, без PSRAM) + ESP32-H2 (NCP).

## Архитектура

ESP32-S3 выступает хостом: WiFi, веб-интерфейс, REST API, WebSocket.
ESP32-H2 — NCP (Network Co-Processor): запускает полный стек ZBOSS и координатор Zigbee.
Связь между чипами — UART (GPIO17 TX, GPIO18 RX), протокол ZNSP поверх SLIP-фреймов с CRC-16.

## Первый запуск

1. Прошить оба чипа через веб-флешер (см. `web-flasher/`)
2. При первом включении шлюз создаёт точку доступа **ZigbeeGW-XXYY** (XXYY — последние байты MAC)
3. Подключиться к точке, пароль: `zigbee1234`
4. Открыть http://192.168.4.1 — веб-интерфейс
5. В настройках указать SSID и пароль домашней WiFi-сети
6. Шлюз перезагрузится и подключится к сети (доступен по mDNS: `zigbee-gw.local`)

## Веб-интерфейс

Доступен по IP-адресу или `http://zigbee-gw.local`. Все действия, изменяющие состояние (POST-запросы), требуют авторизации HTTP Basic Auth.

- **Логин**: `admin`
- **Пароль по умолчанию**: `admin` (можно изменить в настройках, сохраняется в NVS)

---

## Настраиваемые параметры

### Параметры времени выполнения (через веб-интерфейс)

| Параметр | API | По умолчанию | Описание |
|----------|-----|-------------|----------|
| WiFi SSID | `POST /api/settings/wifi` | *(пусто)* | SSID станции. Сохраняется в NVS (`wifi_cfg/ssid`) |
| WiFi пароль | `POST /api/settings/wifi` | *(пусто)* | Пароль станции. Сохраняется в NVS (`wifi_cfg/pass`) |
| Zigbee канал | `POST /api/settings/zigbee` | 25 | Канал 11–26 или 0 (авто). Смена канала = сброс сети + перезагрузка |
| HTTP пароль | `POST /api/settings/password` | `admin` | Пароль Basic Auth. Сохраняется в NVS (`http_auth/password`) |
| Имена устройств | `POST /api/device/rename` | *(пусто)* | Пользовательское имя (до 31 символа). Сохраняется в NVS |
| Определения устройств | `POST /api/defs` | *(пусто)* | JSON с шаблонами авто-привязки. Сохраняется в SPIFFS |

### Параметры компиляции (sdkconfig / Kconfig)

| Параметр | Значение | Описание |
|----------|---------|----------|
| `CONFIG_GW_ZIGBEE_CHANNEL` | 25 | Канал Zigbee по умолчанию. CH25 рекомендуется — WiFi CH1 пересекается с Zigbee CH11-14 |
| `CONFIG_GW_MAX_DEVICES` | 32 (8–64) | Максимум устройств в списке |
| `CONFIG_GW_AP_PASSWORD` | `zigbee1234` | Пароль точки доступа (WPA2, мин. 8 символов) |
| `CONFIG_GW_HTTP_PASSWORD` | `admin` | Пароль HTTP по умолчанию (до изменения через веб) |
| `CONFIG_GW_WIFI_SSID` | *(пусто)* | SSID по умолчанию (перезаписывается из NVS) |
| `CONFIG_GW_WIFI_PASSWORD` | *(пусто)* | Пароль WiFi по умолчанию (перезаписывается из NVS) |

### Аппаратные параметры (sdkconfig.defaults)

| Параметр | Значение | Описание |
|----------|---------|----------|
| Чип | ESP32-S3 | `CONFIG_IDF_TARGET=esp32s3` |
| Flash | 4MB, QIO | `FLASHSIZE_4MB`, `FLASHMODE_QIO` |
| PSRAM | Отключен | WROOM-1 без PSRAM |
| CPU | 240 МГц | `ESP_DEFAULT_CPU_FREQ_MHZ_240` |
| UART TX | GPIO17 | К ESP32-H2 NCP |
| UART RX | GPIO18 | От ESP32-H2 NCP |
| UART скорость | 115200 | Протокол ZNSP |
| Watchdog | 10 сек, паника | `ESP_TASK_WDT_TIMEOUT_S=10` |
| OTA откат | Включён | `BOOTLOADER_APP_ROLLBACK_ENABLE` |
| mDNS | `zigbee-gw` | `LWIP_LOCAL_HOSTNAME` |

---

## Таблица разделов flash

| Раздел | Тип | Смещение | Размер | Назначение |
|--------|-----|----------|--------|------------|
| nvs | data/nvs | 0x9000 | 24 КБ | Настройки, список устройств |
| otadata | data/ota | 0xF000 | 8 КБ | Состояние OTA |
| phy_init | data/phy | 0x11000 | 4 КБ | Калибровка радио |
| ota_0 | app/ota_0 | 0x20000 | 1.75 МБ | Прошивка (слот 0) |
| ota_1 | app/ota_1 | 0x1E0000 | 1.75 МБ | Прошивка (слот 1) |
| zb_storage | data/fat | 0x3A0000 | 16 КБ | NVRAM Zigbee-стека |
| zb_fct | data/fat | 0x3A4000 | 4 КБ | Заводские данные Zigbee |

---

## REST API

Все GET-эндпоинты открыты. Все POST-эндпоинты требуют HTTP Basic Auth (`admin:<пароль>`).

### GET-эндпоинты

| Путь | Описание | Формат ответа |
|------|----------|---------------|
| `/` | Веб-интерфейс | HTML |
| `/api/status` | Статус системы: WiFi, Zigbee, аптайм, память, версия | JSON |
| `/api/devices` | Полный список устройств с эндпоинтами и значениями | JSON |
| `/api/logs` | Кольцевой буфер логов (8 КБ) | text/plain |
| `/api/defs` | Определения устройств (шаблоны привязки) | JSON |

### POST-эндпоинты (требуют авторизации)

| Путь | Тело запроса | Описание |
|------|-------------|----------|
| `/api/permit_join` | `{"duration": 60}` | Открыть сеть для подключения (0–254 сек) |
| `/api/device/cmd` | `{"addr":"0x1234","endpoint":1,"cmd":"on"}` | Команда on/off/toggle |
| `/api/device/rename` | `{"addr":"0x1234","name":"Лампа"}` | Переименовать устройство |
| `/api/device/remove` | `{"addr":"0x1234"}` | Удалить устройство |
| `/api/settings/wifi` | `{"ssid":"MyNet","password":"pass"}` | Сохранить WiFi (перезагрузка) |
| `/api/settings/zigbee` | `{"channel":25}` | Сменить канал (сброс сети + перезагрузка) |
| `/api/settings/password` | `{"password":"newpass"}` | Сменить пароль HTTP |
| `/api/system/restart` | *(пусто)* | Перезагрузка |
| `/api/system/factory-reset` | *(пусто)* | Сброс Zigbee-сети + перезагрузка |
| `/api/ota` | бинарный файл прошивки | OTA-обновление |
| `/api/defs` | JSON с определениями | Сохранить шаблоны привязки |

---

## WebSocket

Подключение: `ws://<ip>/ws` (до 4 клиентов одновременно). Сервер отправляет JSON-сообщения, клиент только читает.

### Типы сообщений

#### `status` — состояние системы
```json
{
  "type": "status",
  "data": {
    "wifi": {"state": "connected", "ssid": "MyNet", "ip": "192.168.1.50", "rssi": -45},
    "zigbee": {"running": true, "channel": 25, "pan_id": "0x1A2B", "devices": 5, "permit_join": false, "permit_join_remaining": 0},
    "system": {"uptime": 3600, "heap": 120000, "firmware": "0.2.7"}
  }
}
```

#### `devices` — полный список устройств
```json
{
  "type": "devices",
  "data": [
    {
      "addr": "0x1234", "ieee": "AA:BB:CC:DD:EE:FF:00:11",
      "name": "Лампа", "manufacturer": "IKEA", "model": "TRADFRI",
      "lqi": 180, "discovery_done": true, "last_seen_sec_ago": 15,
      "endpoints": [
        {"id": 1, "device_id": "0x0100", "on_off": true, "level": 200}
      ]
    }
  ]
}
```

#### `device_update` — обновление одного устройства
Та же схема что у элемента массива `devices`.

#### `device_remove` — устройство удалено
```json
{"type": "device_remove", "data": {"addr": "0x1234"}}
```

#### `permit_join` — изменение состояния подключения
```json
{"type": "permit_join", "data": {"active": true, "remaining": 60}}
```

#### `log` — пакет логов (раз в 500мс)
```json
{"type": "log", "data": "I (12345) zigbee: Device joined\n"}
```

---

## Поддерживаемые свойства устройств

| Свойство | Кластер | Атрибут ID | Тип значения |
|----------|---------|------------|-------------|
| on_off | On/Off (0x0006) | 0x0000 | bool |
| level | Level Control (0x0008) | 0x0000 | uint8 (0–255) |
| temperature | Temperature (0x0402) | 0x0000 | float, °C |
| humidity | Humidity (0x0405) | 0x0000 | float, % |
| pressure | Pressure (0x0403) | 0x0000 | float, hPa |
| illuminance | Illuminance (0x0400) | 0x0000 | uint16, lux |
| occupancy | Occupancy (0x0406) | 0x0000 | bool |

---

## WiFi: логика подключения

1. При старте пытается подключиться к сохранённой WiFi-сети (15 сек таймаут, 5 попыток)
2. Если не удалось — поднимает точку доступа `ZigbeeGW-XXYY` (канал 1, WPA2)
3. В режиме AP каждые 60 секунд пытается переподключиться к STA (10 сек таймаут)
4. При успешном подключении — AP автоматически выключается

---

## Zigbee: подключение устройств

1. Открыть сеть: кнопка «Permit Join» в веб-интерфейсе (или `POST /api/permit_join`)
2. Перевести устройство в режим сопряжения (согласно инструкции устройства)
3. Шлюз автоматически:
   - Обнаруживает устройство (Device Announce)
   - Запрашивает Active Endpoints → Simple Descriptor → Basic Cluster (производитель, модель)
   - Если есть определение в `devices.json` — автоматически привязывает кластеры (bind)
4. Устройство появляется в веб-интерфейсе с атрибутами

---

## Обновление прошивки

### Через веб-интерфейс (OTA)
Загрузить `zigbee-gateway.bin` через раздел «OTA Update» в веб-интерфейсе. Шлюз проверит образ, запишет во второй OTA-слот и перезагрузится. Если новая прошивка не загрузится — автоматический откат.

### Через веб-флешер
Прошивка обоих чипов (S3 и H2) через USB из браузера. Требуется Chrome/Edge. См. `web-flasher/index.html`.

### Через USB
```bash
. $IDF_PATH/export.sh
cd gateway && idf.py flash -p /dev/ttyUSB0
cd ncp && idf.py flash -p /dev/ttyUSB1
```

---

## Сброс к заводским настройкам

Через веб-интерфейс: `POST /api/system/factory-reset`. Стирает разделы `zb_storage` и `zb_fct` (Zigbee-сеть, привязки, ключи). WiFi-настройки и пароль HTTP **сохраняются**.

---

## Внутренние лимиты

| Параметр | Значение |
|----------|---------|
| Макс. устройств | 32 (CONFIG_GW_MAX_DEVICES, 8–64) |
| Макс. эндпоинтов на устройство | 8 |
| Макс. длина имени устройства | 31 символ |
| Макс. WebSocket-клиентов | 4 |
| Буфер логов | 8 КБ (кольцевой) |
| Буфер WS-логов | 2 КБ (пакетный, 500мс) |
| Макс. определений устройств | 32 |
| Макс. размер devices.json | 8 КБ |
| Очередь авто-привязки | 16 операций |
| Размер прошивки (S3) | ~1 МБ (макс. 1.75 МБ) |
| Размер прошивки (H2) | ~713 КБ (макс. 940 КБ) |
