# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Flash

ESP-IDF v5.3.2, target ESP32-S3.

```bash
# Source environment (required before any idf.py command)
. $IDF_PATH/export.sh

# Build (run from gateway/ directory)
idf.py build

# Reconfigure (needed after Kconfig changes)
idf.py reconfigure

# Flash via USB
idf.py flash -p /dev/ttyUSB0

# Monitor serial output
idf.py monitor -p /dev/ttyUSB0

# Interactive config editor
idf.py menuconfig
```

After adding new Kconfig options, always run `idf.py reconfigure` before building — the cached `sdkconfig` won't pick up new symbols otherwise.

## Hardware

ESP32-S3 WROOM-1 (4MB flash, **no PSRAM**) + ESP32-H2 NCP (connected via UART: TX=GPIO17, RX=GPIO18, RST=GPIO7, BOOT=GPIO8). Custom partition table in `partitions.csv` — dual OTA slots (~1.75MB each), Zigbee NVRAM (zb_storage + zb_fct), and SPIFFS (storage) for device definitions.

## Architecture

Single ESP-IDF component (`main/`). All `.c` files compile into one component. `web/index.html` is embedded as a binary blob via `EMBED_TXTFILES`.

### Module Responsibilities

| Module | File | Role |
|--------|------|------|
| Entry | `main.c` | Init orchestration, OTA rollback validation |
| Zigbee | `zigbee.c` | NCP host coordinator, device discovery, auto-bind, log capture |
| Devices | `device_list.c` | In-memory device table (mutex-protected), NVS persistence |
| Definitions | `device_defs.c` | JSON binding templates from SPIFFS (`/storage/devices.json`) |
| HTTP | `web_server.c` | REST API, OTA upload, Basic Auth on POST endpoints |
| WebSocket | `ws_server.c` | Real-time push: status, device updates, log streaming |
| WiFi | `wifi.c` | STA/AP fallback, mDNS, periodic reconnect timer |
| Frontend | `web/index.html` | Single-page app (vanilla JS, no framework) |

### Init Order (app_main)

`zigbee_platform_init()` → NVS → event loop/netif → `device_list_init()` → `wifi_init()` + connect/AP → `wifi_reconnect_timer_init()` → `web_server_start()` → OTA rollback check → `zigbee_ncp_reset()` → `device_defs_init()` → `zigbee_start()`

### Task Model

The Zigbee task (stack 8KB, prio 5) runs `esp_zb_stack_main_loop()` which blocks forever. All Zigbee operations happen through callbacks. HTTP handlers use `esp_zb_lock_acquire/release` to call into the Zigbee API from the HTTPD task.

### Device Discovery Flow

Device announce → `device_add()` → Active EP request → Simple Descriptor for each EP → Read Basic cluster (manufacturer/model) → Match against `device_defs` → Queue auto-bind requests (serialized, max one ZDO bind at a time due to NCP protocol).

### Data Flow: Browser ↔ Firmware

- **Browser → Firmware**: HTTP POST → `web_server.c` handler (auth checked) → Zigbee API or NVS write
- **Firmware → Browser**: Zigbee callback → `ws_notify_*()` → WebSocket broadcast to connected clients
- **Logs**: `esp_log_set_vprintf()` hook → ring buffer (8KB) → WebSocket push (batched ~100ms)

### Thread Safety

- `device_list.c`: FreeRTOS mutex (`device_lock/unlock`) for all device table access
- `device_defs.c`: Separate mutex for definition reads/writes
- `zigbee.c`: `portMUX` spinlock for log ring buffer (ISR-safe)
- `ws_server.c`: `portMUX` spinlock for log batch buffer
- Zigbee state vars (`s_running`, `s_channel`, etc.): volatile, single-writer (Zigbee task)

### NVS Namespaces

| Namespace | Keys | Purpose |
|-----------|------|---------|
| `wifi_cfg` | ssid, pass | Runtime WiFi credentials |
| `http_auth` | password | HTTP admin password |
| `dev_list` | devices | Packed binary device table (v2: includes manufacturer/model) |

### Key Constraints

- **No PSRAM**: Keep allocations small. Device list is static array, not heap.
- **4MB flash**: OTA partition ~1.75MB. Current binary ~1.7MB (4% free). Watch binary size.
- **NVS blob limit**: ~4KB per page. Device list record is ~107 bytes × 32 devices = ~3.4KB.
- **NCP blocking calls**: ZDO bind/leave/permit_join can't run concurrently — auto-bind uses a FIFO queue.
- **Zigbee CH25**: Configured to avoid WiFi CH1 overlap with Zigbee CH11-14.
- **Factory reset**: `esp_zb_factory_reset()` is unreliable from HTTP handler — use direct `esp_partition_erase_range()` on zb_storage + zb_fct partitions.
