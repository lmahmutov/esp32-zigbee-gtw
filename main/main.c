#include <stdio.h>
#include "esp_log.h"
#include "esp_err.h"
#include "nvs_flash.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_ota_ops.h"

#include "wifi.h"
#include "zigbee.h"
#include "device_list.h"
#include "device_defs.h"
#include "web_server.h"
#include "automation.h"

static const char *TAG = "main";

const char *FW_VERSION = "0.3.8 (" __DATE__ " " __TIME__ ")";

void app_main(void)
{
    ESP_LOGI(TAG, "Firmware: %s", FW_VERSION);

    /* Reset H2 NCP first — must boot before host UART starts */
    ESP_ERROR_CHECK(zigbee_ncp_reset());

    /* Zigbee host platform config (starts UART + host task) */
    ESP_ERROR_CHECK(zigbee_platform_init());

    /* NVS */
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    /* Event loop & netif */
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    ESP_ERROR_CHECK(esp_netif_init());

    /* Device list */
    device_list_init();
    device_list_save_timer_init();

    /* WiFi */
    ESP_ERROR_CHECK(wifi_init());

    const char *ssid = CONFIG_GW_WIFI_SSID;
    const char *pass = CONFIG_GW_WIFI_PASSWORD;

    /* Check NVS for runtime-configured credentials */
    nvs_handle_t nvs;
    char nvs_ssid[33] = {0};
    char nvs_pass[65] = {0};
    if (nvs_open("wifi_cfg", NVS_READONLY, &nvs) == ESP_OK) {
        size_t len = sizeof(nvs_ssid);
        if (nvs_get_str(nvs, "ssid", nvs_ssid, &len) == ESP_OK && len > 1) {
            ssid = nvs_ssid;
            len = sizeof(nvs_pass);
            nvs_get_str(nvs, "pass", nvs_pass, &len);
            pass = nvs_pass;
        }
        nvs_close(nvs);
    }

    if (ssid[0] != '\0') {
        ESP_LOGI(TAG, "Connecting to WiFi: %s", ssid);
        wifi_connect(ssid, pass);
    } else {
        ESP_LOGI(TAG, "No WiFi credentials — starting AP mode");
        wifi_start_ap();
    }

    /* WiFi reconnect timer (retries STA periodically while in AP mode) */
    wifi_reconnect_timer_init();

    /* HTTP server */
    ESP_ERROR_CHECK(web_server_start());

    /* OTA rollback validation */
    esp_ota_img_states_t ota_state;
    const esp_partition_t *running = esp_ota_get_running_partition();
    if (esp_ota_get_state_partition(running, &ota_state) == ESP_OK &&
        ota_state == ESP_OTA_IMG_PENDING_VERIFY) {
        ESP_LOGI(TAG, "OTA: validating new firmware");
        esp_ota_mark_app_valid_cancel_rollback();
    }

    /* Device definitions (loads from SPIFFS) */
    device_defs_init();

    /* Automation engine */
    automation_init();

    /* Zigbee coordinator — creates its own task */
    ESP_ERROR_CHECK(zigbee_start());

    /* NCP watchdog — pings NCP periodically, resets on consecutive timeouts */
    zigbee_ncp_watchdog_init();

    /* Start automation scripts after Zigbee init */
    automation_start();

    ESP_LOGI(TAG, "Zigbee Gateway started");
}
