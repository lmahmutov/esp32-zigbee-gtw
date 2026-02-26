#include "wifi.h"

#include <string.h>
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_mac.h"
#include "mdns.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/timers.h"
#include "nvs.h"

static const char *TAG = "wifi";

#define WIFI_CONNECTED_BIT  BIT0
#define WIFI_FAIL_BIT       BIT1
#define WIFI_MAX_RETRY      5
#define RECONNECT_INTERVAL_MS  60000

static EventGroupHandle_t s_wifi_event_group;
static esp_netif_t       *s_sta_netif;
static esp_netif_t       *s_ap_netif;
static wifi_status_t      s_status;
static int                s_retry_count;

static bool s_mdns_inited;

/* Stored STA credentials for reconnect */
static char s_sta_ssid[33];
static char s_sta_pass[65];
static bool s_sta_creds_valid;

/* Reconnect timer + task */
static TimerHandle_t    s_reconnect_timer;
static TaskHandle_t     s_reconnect_task;

static void start_mdns(void)
{
    if (s_mdns_inited) return;
    if (mdns_init() != ESP_OK) return;
    s_mdns_inited = true;
    mdns_hostname_set("zigbee-gw");
    mdns_instance_name_set("Zigbee Gateway");
    mdns_service_add(NULL, "_http", "_tcp", 80, NULL, 0);
}

static void event_handler(void *arg, esp_event_base_t base,
                           int32_t event_id, void *data)
{
    if (base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
        s_status.state = WIFI_STATE_CONNECTING;
    } else if (base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        s_status.state = WIFI_STATE_CONNECTING;
        s_status.ip[0] = '\0';
        if (s_retry_count < WIFI_MAX_RETRY) {
            s_retry_count++;
            ESP_LOGI(TAG, "Retrying connection (%d/%d)", s_retry_count, WIFI_MAX_RETRY);
            esp_wifi_connect();
        } else {
            ESP_LOGW(TAG, "Connection failed after %d retries, switching to AP", WIFI_MAX_RETRY);
            xEventGroupSetBits(s_wifi_event_group, WIFI_FAIL_BIT);
        }
    } else if (base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)data;
        snprintf(s_status.ip, sizeof(s_status.ip), IPSTR, IP2STR(&event->ip_info.ip));
        ESP_LOGI(TAG, "Connected, IP: %s", s_status.ip);
        s_retry_count = 0;
        s_status.state = WIFI_STATE_CONNECTED;
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
        start_mdns();
    } else if (base == WIFI_EVENT && event_id == WIFI_EVENT_AP_STACONNECTED) {
        ESP_LOGI(TAG, "AP: station connected");
    }
}

esp_err_t wifi_init(void)
{
    s_wifi_event_group = xEventGroupCreate();
    memset(&s_status, 0, sizeof(s_status));
    s_status.state = WIFI_STATE_IDLE;

    s_sta_netif = esp_netif_create_default_wifi_sta();
    s_ap_netif  = esp_netif_create_default_wifi_ap();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID, &event_handler, NULL, NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        IP_EVENT, IP_EVENT_STA_GOT_IP, &event_handler, NULL, NULL));

    return ESP_OK;
}

esp_err_t wifi_connect(const char *ssid, const char *password)
{
    /* Store credentials for reconnect timer */
    strncpy(s_sta_ssid, ssid, sizeof(s_sta_ssid) - 1);
    s_sta_ssid[sizeof(s_sta_ssid) - 1] = '\0';
    if (password && password[0]) {
        strncpy(s_sta_pass, password, sizeof(s_sta_pass) - 1);
        s_sta_pass[sizeof(s_sta_pass) - 1] = '\0';
    } else {
        s_sta_pass[0] = '\0';
    }
    s_sta_creds_valid = true;

    s_retry_count = 0;
    xEventGroupClearBits(s_wifi_event_group, WIFI_CONNECTED_BIT | WIFI_FAIL_BIT);

    wifi_config_t wifi_cfg = {0};
    strncpy((char *)wifi_cfg.sta.ssid, ssid, sizeof(wifi_cfg.sta.ssid) - 1);
    if (password && password[0]) {
        strncpy((char *)wifi_cfg.sta.password, password, sizeof(wifi_cfg.sta.password) - 1);
    }
    wifi_cfg.sta.threshold.authmode = password && password[0]
        ? WIFI_AUTH_WPA2_PSK : WIFI_AUTH_OPEN;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_cfg));
    ESP_ERROR_CHECK(esp_wifi_start());

    strncpy(s_status.ssid, ssid, sizeof(s_status.ssid) - 1);

    /* Wait for connection or failure (up to 15s) */
    EventBits_t bits = xEventGroupWaitBits(s_wifi_event_group,
        WIFI_CONNECTED_BIT | WIFI_FAIL_BIT, pdFALSE, pdFALSE,
        pdMS_TO_TICKS(15000));

    if (bits & WIFI_CONNECTED_BIT) {
        return ESP_OK;
    }

    ESP_LOGW(TAG, "STA connection failed, falling back to AP");
    esp_wifi_stop();
    wifi_start_ap();
    return ESP_FAIL;
}

void wifi_start_ap(void)
{
    /* Build SSID as ZigbeeGW-XXYY from last 2 bytes of MAC */
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_SOFTAP);
    char ap_ssid[32];
    snprintf(ap_ssid, sizeof(ap_ssid), "ZigbeeGW-%02X%02X", mac[4], mac[5]);

    wifi_config_t ap_cfg = {
        .ap = {
            .channel = 1,
            .max_connection = 4,
            .authmode = WIFI_AUTH_WPA2_PSK,
        },
    };
    strncpy((char *)ap_cfg.ap.ssid, ap_ssid, sizeof(ap_cfg.ap.ssid));
    ap_cfg.ap.ssid_len = strlen(ap_ssid);
    strncpy((char *)ap_cfg.ap.password, CONFIG_GW_AP_PASSWORD, sizeof(ap_cfg.ap.password));

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &ap_cfg));
    ESP_ERROR_CHECK(esp_wifi_start());

    strncpy(s_status.ssid, ap_ssid, sizeof(s_status.ssid));
    strncpy(s_status.ip, "192.168.4.1", sizeof(s_status.ip));
    s_status.state = WIFI_STATE_AP_ACTIVE;

    ESP_LOGI(TAG, "AP started: %s (192.168.4.1, WPA2)", ap_ssid);
    start_mdns();
}

void wifi_get_status(wifi_status_t *out)
{
    *out = s_status;
    if (s_status.state == WIFI_STATE_CONNECTED) {
        wifi_ap_record_t ap;
        if (esp_wifi_sta_get_ap_info(&ap) == ESP_OK) {
            out->rssi = ap.rssi;
        }
    }
}

bool wifi_is_connected(void)
{
    return s_status.state == WIFI_STATE_CONNECTED;
}

/* ── WiFi reconnect timer ─────────────────────────────── */

static void reconnect_task(void *arg)
{
    (void)arg;
    for (;;) {
        ulTaskNotifyTake(pdTRUE, portMAX_DELAY);

        if (s_status.state != WIFI_STATE_AP_ACTIVE || !s_sta_creds_valid) {
            continue;
        }

        ESP_LOGI(TAG, "Reconnect: attempting STA connection to '%s'", s_sta_ssid);

        /* Stop current AP */
        esp_wifi_stop();

        /* Try STA */
        s_retry_count = 0;
        xEventGroupClearBits(s_wifi_event_group, WIFI_CONNECTED_BIT | WIFI_FAIL_BIT);

        wifi_config_t wifi_cfg = {0};
        strncpy((char *)wifi_cfg.sta.ssid, s_sta_ssid, sizeof(wifi_cfg.sta.ssid) - 1);
        if (s_sta_pass[0]) {
            strncpy((char *)wifi_cfg.sta.password, s_sta_pass, sizeof(wifi_cfg.sta.password) - 1);
        }
        wifi_cfg.sta.threshold.authmode = s_sta_pass[0]
            ? WIFI_AUTH_WPA2_PSK : WIFI_AUTH_OPEN;

        esp_wifi_set_mode(WIFI_MODE_STA);
        esp_wifi_set_config(WIFI_IF_STA, &wifi_cfg);
        esp_wifi_start();

        /* Wait up to 10s */
        EventBits_t bits = xEventGroupWaitBits(s_wifi_event_group,
            WIFI_CONNECTED_BIT | WIFI_FAIL_BIT, pdFALSE, pdFALSE,
            pdMS_TO_TICKS(10000));

        if (bits & WIFI_CONNECTED_BIT) {
            ESP_LOGI(TAG, "Reconnect: STA connected successfully");
            /* Stay in STA mode, task sleeps until next notification */
        } else {
            ESP_LOGW(TAG, "Reconnect: STA failed, restarting AP");
            esp_wifi_stop();
            wifi_start_ap();
        }
    }
}

static void reconnect_timer_cb(TimerHandle_t timer)
{
    (void)timer;
    if (s_reconnect_task) {
        xTaskNotifyGive(s_reconnect_task);
    }
}

void wifi_reconnect_timer_init(void)
{
    xTaskCreate(reconnect_task, "wifi_reconn", 3072, NULL, 3, &s_reconnect_task);

    s_reconnect_timer = xTimerCreate("wifi_reconn", pdMS_TO_TICKS(RECONNECT_INTERVAL_MS),
                                      pdTRUE, NULL, reconnect_timer_cb);
    xTimerStart(s_reconnect_timer, 0);
    ESP_LOGI(TAG, "WiFi reconnect timer started (%ds interval)", RECONNECT_INTERVAL_MS / 1000);
}
