# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build

ESP-IDF v5.3.2, target ESP32-H2.

```bash
. $IDF_PATH/export.sh
idf.py set-target esp32h2   # only needed once
idf.py build
idf.py flash -p /dev/ttyUSB0
idf.py monitor -p /dev/ttyUSB0
idf.py menuconfig           # Kconfig: Component config → Zigbee Network Co-processor
```

## What This Project Is

ESP32-H2 NCP (Network Co-Processor) firmware for a Zigbee gateway. The H2 runs the full ZBOSS Zigbee coordinator stack. The sibling project `../gateway/` (ESP32-S3) acts as a thin host — it sends ZNSP commands over UART and receives notifications (device join, attribute reports, etc.).

```
ESP32-S3 (gateway)  ──UART (SLIP+CRC16)──>  ESP32-H2 (this NCP)
  WiFi, web UI, REST API                      ZBOSS stack, 802.15.4 radio
```

## Architecture

Layered design inside `components/esp-zigbee-ncp/`:

| Layer | File | Role |
|-------|------|------|
| Entry | `esp_ncp_main.c` | Lifecycle (init/start/stop), FreeRTOS event queue, main task |
| Transport | `esp_ncp_bus.c` | UART driver, SLIP pattern detection, stream buffers (20KB each) |
| Framing | `esp_ncp_frame.c` | 8-byte header + payload + CRC16, SLIP encode/decode |
| SLIP | `slip.c` | Byte stuffing (0xC0 frame boundary, 0xDB escape) |
| Commands | `esp_ncp_zb.c` | ZNSP dispatch table: frame ID → handler function (1972 lines) |

**Frame IDs** (defined in `src/priv/esp_ncp_zb.h`):
- `0x0000–0x002D` — Network: init, form, start, channel, permit join, etc.
- `0x0100–0x0108` — ZCL: endpoint add/del, attribute read/write, report
- `0x0200–0x0204` — ZDO: bind, unbind, match desc, active EP, simple desc
- `0x0300–0x0302` — APS: data request, indication, confirm

**Response types**: response (type=1) for request/reply, notification (type=2) for async events.

## Key Details

- **Xiaomi compatibility**: `app_main()` sets TC rejoin policies before `esp_ncp_start()` — these 5 security calls are critical for Xiaomi device pairing
- **UART config**: UART1, 115200 baud, no flow control. Pin assignment is auto (default H2 pins). The gateway side uses TX=GPIO17, RX=GPIO18
- **Partition table**: dual OTA slots (940KB each) + `zb_storage` (16KB) + `zb_fct` (1KB)
- **Dependencies**: `esp-zigbee-lib ~1.6.0` and `esp-zboss-lib ~1.6.0` via IDF Component Manager (managed_components/)
