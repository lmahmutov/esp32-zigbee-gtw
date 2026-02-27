#pragma once

#include <stdbool.h>
#include "esp_err.h"
#include "esp_netif.h"

typedef enum {
    WIFI_STATE_IDLE,
    WIFI_STATE_CONNECTING,
    WIFI_STATE_CONNECTED,
    WIFI_STATE_AP_ACTIVE,
} wifi_state_t;

typedef struct {
    wifi_state_t state;
    char         ssid[33];
    char         ip[16];
    int8_t       rssi;
} wifi_status_t;

esp_err_t wifi_init(void);
esp_err_t wifi_connect(const char *ssid, const char *password);
void      wifi_start_ap(void);
void      wifi_get_status(wifi_status_t *out);
bool      wifi_is_connected(void);
void      wifi_reconnect_timer_init(void);
