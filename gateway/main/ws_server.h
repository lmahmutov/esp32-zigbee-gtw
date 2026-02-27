#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "esp_http_server.h"
#include "device_list.h"
#include "cJSON.h"

/* Initialize WebSocket server: register /ws endpoint, start log timer */
void ws_init(httpd_handle_t server);

/* Remove a client fd (called from session close callback) */
void ws_remove_client(int fd);

/* Push notifications — safe to call from any task */
void ws_notify_status(void);
void ws_notify_devices(void);
void ws_notify_device_update(uint16_t short_addr);
void ws_notify_device_remove(uint16_t short_addr);
void ws_notify_permit_join(bool active, uint8_t remaining);
void ws_notify_log(const char *text, int len);

/* Shared JSON builders (used by both WS push and HTTP handlers) */
cJSON *ws_build_status_json(void);
cJSON *ws_build_device_json(const zb_device_t *dev);
cJSON *ws_build_devices_json(void);
