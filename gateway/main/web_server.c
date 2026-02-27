#include "web_server.h"
#include "ws_server.h"
#include "wifi.h"
#include "zigbee.h"
#include "device_list.h"
#include "device_defs.h"
#include "automation.h"

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "esp_log.h"
#include "esp_http_server.h"
#include "esp_timer.h"
#include "esp_ota_ops.h"
#include "esp_app_format.h"
#include "cJSON.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "mbedtls/base64.h"

static const char *TAG = "httpd";
static httpd_handle_t s_server;

extern const char *FW_VERSION;

/* Embedded index.html */
extern const char index_html_start[] asm("_binary_index_html_start");
extern const char index_html_end[]   asm("_binary_index_html_end");

/* Embedded gzipped Blockly JS */
extern const uint8_t blockly_js_gz_start[] asm("_binary_blockly_js_gz_start");
extern const uint8_t blockly_js_gz_end[]   asm("_binary_blockly_js_gz_end");

/* ── HTTP Basic Auth ─────────────────────────────────────── */

static char s_auth_password[33];

static void auth_load_password(void)
{
    nvs_handle_t nvs;
    if (nvs_open("http_auth", NVS_READONLY, &nvs) == ESP_OK) {
        size_t len = sizeof(s_auth_password);
        if (nvs_get_str(nvs, "password", s_auth_password, &len) == ESP_OK && len > 1) {
            nvs_close(nvs);
            return;
        }
        nvs_close(nvs);
    }
    /* Fallback to Kconfig default */
    strncpy(s_auth_password, CONFIG_GW_HTTP_PASSWORD, sizeof(s_auth_password) - 1);
    s_auth_password[sizeof(s_auth_password) - 1] = '\0';
}

static esp_err_t send_auth_required(httpd_req_t *req)
{
    httpd_resp_set_status(req, "401 Unauthorized");
    httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"ZigbeeGateway\"");
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"error\":\"Authentication required\"}");
    return ESP_OK;
}

static bool check_auth(httpd_req_t *req)
{
    char auth_hdr[128];
    if (httpd_req_get_hdr_value_str(req, "Authorization", auth_hdr, sizeof(auth_hdr)) != ESP_OK) {
        return false;
    }

    /* Expect "Basic <base64>" */
    if (strncmp(auth_hdr, "Basic ", 6) != 0) {
        return false;
    }

    const char *b64 = auth_hdr + 6;
    unsigned char decoded[96];
    size_t decoded_len = 0;
    if (mbedtls_base64_decode(decoded, sizeof(decoded) - 1, &decoded_len,
                              (const unsigned char *)b64, strlen(b64)) != 0) {
        return false;
    }
    decoded[decoded_len] = '\0';

    /* Expected: "admin:<password>" */
    char expected[64];
    snprintf(expected, sizeof(expected), "admin:%s", s_auth_password);

    return strcmp((char *)decoded, expected) == 0;
}

#define REQUIRE_AUTH(req) do { \
    if (!check_auth(req)) return send_auth_required(req); \
} while(0)

/* ── Helpers ──────────────────────────────────────────── */

static esp_err_t send_error(httpd_req_t *req, int code, const char *msg);

static esp_err_t send_json(httpd_req_t *req, cJSON *json)
{
    if (!json) return send_error(req, 500, "Out of memory");
    char *str = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);
    if (!str) return send_error(req, 500, "JSON serialize failed");
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, str);
    free(str);
    return ESP_OK;
}

static esp_err_t send_error(httpd_req_t *req, int code, const char *msg)
{
    httpd_resp_set_status(req, code == 400 ? "400 Bad Request" : "500 Internal Server Error");
    httpd_resp_set_type(req, "application/json");
    char buf[128];
    snprintf(buf, sizeof(buf), "{\"error\":\"%s\"}", msg);
    httpd_resp_sendstr(req, buf);
    return ESP_OK;
}

/* ── GET / — serve web UI ─────────────────────────────── */

static esp_err_t handler_index(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    httpd_resp_set_hdr(req, "Cache-Control", "no-cache");
    httpd_resp_send(req, index_html_start, index_html_end - index_html_start);
    return ESP_OK;
}

/* ── GET /blockly.js — serve embedded gzipped Blockly ── */

static esp_err_t handler_blockly_js(httpd_req_t *req)
{
    httpd_resp_set_type(req, "application/javascript");
    httpd_resp_set_hdr(req, "Content-Encoding", "gzip");
    httpd_resp_set_hdr(req, "Cache-Control", "public, max-age=86400");
    httpd_resp_send(req, (const char *)blockly_js_gz_start,
                    blockly_js_gz_end - blockly_js_gz_start);
    return ESP_OK;
}

/* ── GET /api/status ──────────────────────────────────── */

static esp_err_t handler_status(httpd_req_t *req)
{
    return send_json(req, ws_build_status_json());
}

/* ── GET /api/devices ─────────────────────────────────── */

static esp_err_t handler_devices(httpd_req_t *req)
{
    return send_json(req, ws_build_devices_json());
}

/* ── POST /api/permit_join ────────────────────────────── */

static esp_err_t handler_permit_join(httpd_req_t *req)
{
    REQUIRE_AUTH(req);
    if (req->content_len <= 0 || req->content_len >= 64)
        return send_error(req, 400, "Invalid body size");
    char buf[64];
    int len = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (len <= 0) return send_error(req, 400, "Empty body");
    buf[len] = '\0';

    cJSON *json = cJSON_Parse(buf);
    if (!json) return send_error(req, 400, "Invalid JSON");

    int duration = 60;
    cJSON *dur = cJSON_GetObjectItem(json, "duration");
    if (dur && cJSON_IsNumber(dur)) {
        duration = dur->valueint;
        if (duration < 0) duration = 0;
        if (duration > 254) duration = 254;
    }
    cJSON_Delete(json);

    zigbee_permit_join((uint8_t)duration);

    cJSON *resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "ok", true);
    cJSON_AddNumberToObject(resp, "duration", duration);
    return send_json(req, resp);
}

/* ── POST /api/device/cmd ─────────────────────────────── */

static esp_err_t handler_device_cmd(httpd_req_t *req)
{
    REQUIRE_AUTH(req);
    if (req->content_len <= 0 || req->content_len >= 128)
        return send_error(req, 400, "Invalid body size");
    char buf[128];
    int len = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (len <= 0) return send_error(req, 400, "Empty body");
    buf[len] = '\0';

    cJSON *json = cJSON_Parse(buf);
    if (!json) return send_error(req, 400, "Invalid JSON");

    cJSON *j_addr = cJSON_GetObjectItem(json, "addr");
    cJSON *j_ep   = cJSON_GetObjectItem(json, "endpoint");
    cJSON *j_cmd  = cJSON_GetObjectItem(json, "cmd");

    if (!j_addr || !cJSON_IsString(j_addr) ||
        !j_ep   || !cJSON_IsNumber(j_ep) ||
        !j_cmd  || !cJSON_IsString(j_cmd)) {
        cJSON_Delete(json);
        return send_error(req, 400, "Missing or invalid addr/endpoint/cmd");
    }

    uint16_t addr = (uint16_t)strtol(j_addr->valuestring, NULL, 0);
    uint8_t endpoint = (uint8_t)j_ep->valueint;
    const char *cmd = j_cmd->valuestring;

    if (strcmp(cmd, "on") == 0) {
        zigbee_send_on_off(addr, endpoint, 1);
    } else if (strcmp(cmd, "off") == 0) {
        zigbee_send_on_off(addr, endpoint, 0);
    } else if (strcmp(cmd, "toggle") == 0) {
        zigbee_send_on_off(addr, endpoint, 2);
    } else {
        cJSON_Delete(json);
        return send_error(req, 400, "Unknown cmd");
    }

    cJSON_Delete(json);

    cJSON *resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "ok", true);
    return send_json(req, resp);
}

/* ── POST /api/device/rename ──────────────────────────── */

static esp_err_t handler_device_rename(httpd_req_t *req)
{
    REQUIRE_AUTH(req);
    if (req->content_len <= 0 || req->content_len >= 128)
        return send_error(req, 400, "Invalid body size");
    char buf[128];
    int len = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (len <= 0) return send_error(req, 400, "Empty body");
    buf[len] = '\0';

    cJSON *json = cJSON_Parse(buf);
    if (!json) return send_error(req, 400, "Invalid JSON");

    cJSON *j_addr = cJSON_GetObjectItem(json, "addr");
    cJSON *j_name = cJSON_GetObjectItem(json, "name");
    if (!j_addr || !cJSON_IsString(j_addr) || !j_name || !cJSON_IsString(j_name)) {
        cJSON_Delete(json);
        return send_error(req, 400, "Missing or invalid addr/name");
    }

    uint16_t addr = (uint16_t)strtol(j_addr->valuestring, NULL, 0);

    device_lock();
    int idx = device_find(addr);
    if (idx >= 0) {
        zb_device_t *dev = device_get(idx);
        strncpy(dev->name, j_name->valuestring, DEV_NAME_LEN - 1);
        dev->name[DEV_NAME_LEN - 1] = '\0';
    }
    device_unlock();
    if (idx >= 0) device_list_save_deferred();

    cJSON_Delete(json);

    cJSON *resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "ok", idx >= 0);
    return send_json(req, resp);
}

/* ── POST /api/settings/wifi ──────────────────────────── */

static esp_err_t handler_wifi_settings(httpd_req_t *req)
{
    REQUIRE_AUTH(req);
    if (req->content_len <= 0 || req->content_len >= 192)
        return send_error(req, 400, "Invalid body size");
    char buf[192];
    int len = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (len <= 0) return send_error(req, 400, "Empty body");
    buf[len] = '\0';

    cJSON *json = cJSON_Parse(buf);
    if (!json) return send_error(req, 400, "Invalid JSON");

    cJSON *j_ssid = cJSON_GetObjectItem(json, "ssid");
    cJSON *j_pass = cJSON_GetObjectItem(json, "password");
    if (!j_ssid || !cJSON_IsString(j_ssid)) {
        cJSON_Delete(json);
        return send_error(req, 400, "Missing ssid");
    }

    /* Store to NVS */
    nvs_handle_t nvs;
    esp_err_t err = nvs_open("wifi_cfg", NVS_READWRITE, &nvs);
    if (err == ESP_OK) {
        nvs_set_str(nvs, "ssid", j_ssid->valuestring);
        if (j_pass && cJSON_IsString(j_pass)) {
            nvs_set_str(nvs, "pass", j_pass->valuestring);
        } else {
            nvs_set_str(nvs, "pass", "");
        }
        nvs_commit(nvs);
        nvs_close(nvs);
    }

    cJSON_Delete(json);

    cJSON *resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "ok", err == ESP_OK);
    cJSON_AddStringToObject(resp, "message", "WiFi credentials saved. Restart to apply.");
    return send_json(req, resp);
}

/* ── POST /api/system/restart ─────────────────────────── */

static esp_err_t handler_restart(httpd_req_t *req)
{
    REQUIRE_AUTH(req);
    cJSON *resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "ok", true);
    send_json(req, resp);

    ESP_LOGI(TAG, "Restarting in 1 second...");
    vTaskDelay(pdMS_TO_TICKS(1000));
    esp_restart();
    return ESP_OK;
}

/* ── POST /api/system/factory-reset ───────────────────── */

static esp_err_t handler_factory_reset(httpd_req_t *req)
{
    REQUIRE_AUTH(req);
    cJSON *resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "ok", true);
    cJSON_AddStringToObject(resp, "message", "Factory reset, restarting...");
    send_json(req, resp);

    vTaskDelay(pdMS_TO_TICKS(500));
    zigbee_factory_reset();
    return ESP_OK;
}

/* ── POST /api/device/remove ──────────────────────────── */

static esp_err_t handler_device_remove(httpd_req_t *req)
{
    REQUIRE_AUTH(req);
    if (req->content_len <= 0 || req->content_len >= 64)
        return send_error(req, 400, "Invalid body size");
    char buf[64];
    int len = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (len <= 0) return send_error(req, 400, "Empty body");
    buf[len] = '\0';

    cJSON *json = cJSON_Parse(buf);
    if (!json) return send_error(req, 400, "Invalid JSON");

    cJSON *j_addr = cJSON_GetObjectItem(json, "addr");
    if (!j_addr || !cJSON_IsString(j_addr)) {
        cJSON_Delete(json);
        return send_error(req, 400, "Missing or invalid addr");
    }

    uint16_t addr = (uint16_t)strtol(j_addr->valuestring, NULL, 0);

    device_lock();
    int idx = device_find(addr);
    if (idx >= 0) {
        device_remove(idx);
    }
    device_unlock();
    if (idx >= 0) device_list_save_deferred();

    cJSON_Delete(json);

    cJSON *resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "ok", idx >= 0);
    return send_json(req, resp);
}

/* ── POST /api/settings/zigbee ────────────────────────── */

static esp_err_t handler_zigbee_settings(httpd_req_t *req)
{
    REQUIRE_AUTH(req);
    if (req->content_len <= 0 || req->content_len >= 128)
        return send_error(req, 400, "Invalid body size");
    char buf[128];
    int len = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (len <= 0) return send_error(req, 400, "Empty body");
    buf[len] = '\0';

    cJSON *json = cJSON_Parse(buf);
    if (!json) return send_error(req, 400, "Invalid JSON");

    cJSON *j_ch = cJSON_GetObjectItem(json, "channel");
    if (!j_ch || !cJSON_IsNumber(j_ch)) {
        cJSON_Delete(json);
        return send_error(req, 400, "Missing channel");
    }

    int channel = j_ch->valueint;
    cJSON_Delete(json);

    if (channel != 0 && (channel < 11 || channel > 26)) {
        return send_error(req, 400, "Channel must be 11-26 or 0 for auto");
    }

    cJSON *resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "ok", true);
    cJSON_AddStringToObject(resp, "message", "Channel saved. Resetting Zigbee network...");
    send_json(req, resp);

    /* This will factory reset and restart */
    zigbee_set_channel((uint8_t)channel);
    return ESP_OK;
}

/* ── GET /api/logs ────────────────────────────────────── */

static esp_err_t handler_logs(httpd_req_t *req)
{
    char *buf = malloc(8192);
    if (!buf) return send_error(req, 500, "Out of memory");

    size_t len = zigbee_get_log(buf, 8192);
    httpd_resp_set_type(req, "text/plain");
    httpd_resp_set_hdr(req, "Cache-Control", "no-cache");
    httpd_resp_send(req, buf, len);
    free(buf);
    return ESP_OK;
}

/* ── POST /api/ota — firmware upload ──────────────────── */

static esp_err_t handler_ota(httpd_req_t *req)
{
    REQUIRE_AUTH(req);

    /* Validate content length */
    if (req->content_len <= 0) {
        return send_error(req, 400, "Empty firmware image");
    }

    const esp_partition_t *update_part = esp_ota_get_next_update_partition(NULL);
    if (!update_part) {
        return send_error(req, 500, "No OTA partition found");
    }

    if (req->content_len > (int)update_part->size) {
        ESP_LOGE(TAG, "OTA image too large: %d > %lu", req->content_len, (unsigned long)update_part->size);
        return send_error(req, 400, "Firmware image too large for partition");
    }

    ESP_LOGI(TAG, "OTA update started, size=%d", req->content_len);

    esp_ota_handle_t ota_handle;
    esp_err_t err = esp_ota_begin(update_part, OTA_WITH_SEQUENTIAL_WRITES, &ota_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_begin failed: %s", esp_err_to_name(err));
        return send_error(req, 500, "OTA begin failed");
    }

    char *buf = malloc(8192);
    if (!buf) {
        esp_ota_abort(ota_handle);
        return send_error(req, 500, "Out of memory");
    }

    int remaining = req->content_len;
    int received = 0;
    bool failed = false;
    int timeout_retries = 0;

    while (remaining > 0) {
        int to_read = remaining < 8192 ? remaining : 8192;
        int ret = httpd_req_recv(req, buf, to_read);
        if (ret <= 0) {
            if (ret == HTTPD_SOCK_ERR_TIMEOUT && ++timeout_retries < 30) continue;
            ESP_LOGE(TAG, "OTA recv error (ret=%d, retries=%d)", ret, timeout_retries);
            failed = true;
            break;
        }
        timeout_retries = 0;
        err = esp_ota_write(ota_handle, buf, ret);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "esp_ota_write failed: %s", esp_err_to_name(err));
            failed = true;
            break;
        }
        remaining -= ret;
        received += ret;
    }
    free(buf);

    if (failed) {
        esp_ota_abort(ota_handle);
        return send_error(req, 500, "OTA write failed");
    }

    err = esp_ota_end(ota_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_end failed: %s", esp_err_to_name(err));
        return send_error(req, 500, "OTA validation failed");
    }

    err = esp_ota_set_boot_partition(update_part);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_set_boot_partition failed: %s", esp_err_to_name(err));
        return send_error(req, 500, "Set boot partition failed");
    }

    ESP_LOGI(TAG, "OTA success (%d bytes), restarting...", received);

    cJSON *resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "ok", true);
    cJSON_AddNumberToObject(resp, "size", received);
    cJSON_AddStringToObject(resp, "message", "Firmware updated. Restarting...");
    send_json(req, resp);

    vTaskDelay(pdMS_TO_TICKS(1000));
    esp_restart();
    return ESP_OK;
}

/* ── GET /api/defs ────────────────────────────────────── */

static esp_err_t handler_defs_get(httpd_req_t *req)
{
    char *json = device_defs_get_json();
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Cache-Control", "no-cache");
    if (json) {
        httpd_resp_sendstr(req, json);
        free(json);
    } else {
        httpd_resp_sendstr(req, "{}");
    }
    return ESP_OK;
}

/* ── POST /api/defs ───────────────────────────────────── */

static esp_err_t handler_defs_post(httpd_req_t *req)
{
    REQUIRE_AUTH(req);
    if (req->content_len <= 0 || req->content_len > 4096) {
        return send_error(req, 400, "Body must be 1-4096 bytes");
    }

    char *buf = malloc(req->content_len + 1);
    if (!buf) return send_error(req, 500, "Out of memory");

    int received = 0;
    int timeout_retries = 0;
    while (received < req->content_len) {
        int ret = httpd_req_recv(req, buf + received, req->content_len - received);
        if (ret <= 0) {
            if (ret == HTTPD_SOCK_ERR_TIMEOUT && ++timeout_retries < 10) continue;
            free(buf);
            return send_error(req, 400, "Receive error");
        }
        timeout_retries = 0;
        received += ret;
    }
    buf[received] = '\0';

    int rc = device_defs_save(buf, received);
    free(buf);

    if (rc != 0) {
        return send_error(req, 400, "Invalid JSON or write failed");
    }

    cJSON *resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "ok", true);
    return send_json(req, resp);
}

/* ── POST /api/settings/password ──────────────────────── */

static esp_err_t handler_password(httpd_req_t *req)
{
    REQUIRE_AUTH(req);
    if (req->content_len <= 0 || req->content_len >= 128)
        return send_error(req, 400, "Invalid body size");
    char buf[128];
    int len = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (len <= 0) return send_error(req, 400, "Empty body");
    buf[len] = '\0';

    cJSON *json = cJSON_Parse(buf);
    if (!json) return send_error(req, 400, "Invalid JSON");

    cJSON *j_pw = cJSON_GetObjectItem(json, "password");
    if (!j_pw || !cJSON_IsString(j_pw) || strlen(j_pw->valuestring) == 0) {
        cJSON_Delete(json);
        return send_error(req, 400, "Missing or empty password");
    }

    /* Save to NVS */
    nvs_handle_t nvs;
    esp_err_t err = nvs_open("http_auth", NVS_READWRITE, &nvs);
    if (err == ESP_OK) {
        nvs_set_str(nvs, "password", j_pw->valuestring);
        nvs_commit(nvs);
        nvs_close(nvs);
    }

    /* Update in-memory password */
    strncpy(s_auth_password, j_pw->valuestring, sizeof(s_auth_password) - 1);
    s_auth_password[sizeof(s_auth_password) - 1] = '\0';

    cJSON_Delete(json);

    ESP_LOGI(TAG, "HTTP password changed");

    cJSON *resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "ok", err == ESP_OK);
    return send_json(req, resp);
}

/* ── Automation API ────────────────────────────────────── */

/* Helper to receive JSON body into a heap buffer */
static char *recv_body(httpd_req_t *req, int max_len)
{
    if (req->content_len <= 0 || req->content_len > max_len) return NULL;
    char *buf = malloc(req->content_len + 1);
    if (!buf) return NULL;
    int received = 0, retries = 0;
    while (received < req->content_len) {
        int ret = httpd_req_recv(req, buf + received, req->content_len - received);
        if (ret <= 0) {
            if (ret == HTTPD_SOCK_ERR_TIMEOUT && ++retries < 10) continue;
            free(buf);
            return NULL;
        }
        retries = 0;
        received += ret;
    }
    buf[received] = '\0';
    return buf;
}

/* GET /api/automations — list scripts, or ?id=xxx for single script */
static esp_err_t handler_automations_get(httpd_req_t *req)
{
    /* Check for ?id=xxx query parameter */
    char query[64] = {0};
    char id[AUTO_ID_LEN] = {0};
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK) {
        httpd_query_key_value(query, "id", id, sizeof(id));
    }

    if (id[0]) {
        /* Single script */
        auto_script_meta_t meta;
        char *lua_code = malloc(4096);
        char *blockly_xml = malloc(8192);
        if (!lua_code || !blockly_xml) {
            free(lua_code); free(blockly_xml);
            return send_error(req, 500, "Out of memory");
        }
        lua_code[0] = 0;
        blockly_xml[0] = 0;

        if (!automation_get_script(id, lua_code, 4096, blockly_xml, 8192, &meta)) {
            free(lua_code); free(blockly_xml);
            return send_error(req, 400, "Script not found");
        }

        cJSON *obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "id", meta.id);
        cJSON_AddStringToObject(obj, "name", meta.name);
        cJSON_AddBoolToObject(obj, "enabled", meta.enabled);
        cJSON_AddBoolToObject(obj, "running", meta.running);
        cJSON_AddStringToObject(obj, "lua_code", lua_code);
        cJSON_AddStringToObject(obj, "blockly_xml", blockly_xml);
        free(lua_code); free(blockly_xml);
        return send_json(req, obj);
    }

    /* List all scripts */
    auto_script_meta_t scripts[AUTO_MAX_SCRIPTS];
    int count = automation_list_scripts(scripts, AUTO_MAX_SCRIPTS);

    cJSON *arr = cJSON_CreateArray();
    for (int i = 0; i < count; i++) {
        cJSON *obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "id", scripts[i].id);
        cJSON_AddStringToObject(obj, "name", scripts[i].name);
        cJSON_AddBoolToObject(obj, "enabled", scripts[i].enabled);
        cJSON_AddBoolToObject(obj, "running", scripts[i].running);
        cJSON_AddItemToArray(arr, obj);
    }
    return send_json(req, arr);
}

/* POST /api/automations — create/update script */
static esp_err_t handler_automations_save(httpd_req_t *req)
{
    REQUIRE_AUTH(req);
    char *buf = recv_body(req, 16384);
    if (!buf) return send_error(req, 400, "Invalid body");

    cJSON *json = cJSON_Parse(buf);
    free(buf);
    if (!json) return send_error(req, 400, "Invalid JSON");

    cJSON *j_id   = cJSON_GetObjectItem(json, "id");
    cJSON *j_name = cJSON_GetObjectItem(json, "name");
    cJSON *j_code = cJSON_GetObjectItem(json, "lua_code");
    cJSON *j_xml  = cJSON_GetObjectItem(json, "blockly_xml");
    cJSON *j_en   = cJSON_GetObjectItem(json, "enabled");

    if (!j_id || !cJSON_IsString(j_id) || !j_id->valuestring[0]) {
        cJSON_Delete(json);
        return send_error(req, 400, "Missing id");
    }

    bool enabled = j_en && cJSON_IsTrue(j_en);

    bool ok = automation_save_script(
        j_id->valuestring,
        (j_name && cJSON_IsString(j_name)) ? j_name->valuestring : j_id->valuestring,
        (j_code && cJSON_IsString(j_code)) ? j_code->valuestring : "",
        (j_xml  && cJSON_IsString(j_xml))  ? j_xml->valuestring  : "",
        enabled
    );
    cJSON_Delete(json);

    cJSON *resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "ok", ok);
    return send_json(req, resp);
}

/* POST /api/automations/delete */
static esp_err_t handler_automations_delete(httpd_req_t *req)
{
    REQUIRE_AUTH(req);
    char *buf = recv_body(req, 256);
    if (!buf) return send_error(req, 400, "Invalid body");

    cJSON *json = cJSON_Parse(buf);
    free(buf);
    if (!json) return send_error(req, 400, "Invalid JSON");

    cJSON *j_id = cJSON_GetObjectItem(json, "id");
    if (!j_id || !cJSON_IsString(j_id)) {
        cJSON_Delete(json);
        return send_error(req, 400, "Missing id");
    }

    bool ok = automation_delete_script(j_id->valuestring);
    cJSON_Delete(json);

    cJSON *resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "ok", ok);
    return send_json(req, resp);
}

/* POST /api/automations/toggle */
static esp_err_t handler_automations_toggle(httpd_req_t *req)
{
    REQUIRE_AUTH(req);
    char *buf = recv_body(req, 256);
    if (!buf) return send_error(req, 400, "Invalid body");

    cJSON *json = cJSON_Parse(buf);
    free(buf);
    if (!json) return send_error(req, 400, "Invalid JSON");

    cJSON *j_id = cJSON_GetObjectItem(json, "id");
    if (!j_id || !cJSON_IsString(j_id)) {
        cJSON_Delete(json);
        return send_error(req, 400, "Missing id");
    }

    bool ok = automation_toggle_script(j_id->valuestring);
    cJSON_Delete(json);

    cJSON *resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "ok", ok);
    return send_json(req, resp);
}

/* POST /api/automations/run — test-run a saved script */
static esp_err_t handler_automations_run(httpd_req_t *req)
{
    REQUIRE_AUTH(req);
    char *buf = recv_body(req, 8192);
    if (!buf) return send_error(req, 400, "Invalid body");

    cJSON *json = cJSON_Parse(buf);
    free(buf);
    if (!json) return send_error(req, 400, "Invalid JSON");

    char *logs = NULL;
    cJSON *j_id   = cJSON_GetObjectItem(json, "id");
    cJSON *j_code = cJSON_GetObjectItem(json, "lua_code");

    if (j_code && cJSON_IsString(j_code) && j_code->valuestring[0]) {
        /* Inline code execution */
        logs = automation_run_inline(j_code->valuestring);
    } else if (j_id && cJSON_IsString(j_id)) {
        /* Run saved script */
        logs = automation_run_test(j_id->valuestring);
    } else {
        cJSON_Delete(json);
        return send_error(req, 400, "Missing id or lua_code");
    }
    cJSON_Delete(json);

    cJSON *resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "ok", logs != NULL);
    cJSON_AddStringToObject(resp, "logs", logs ? logs : "Script not found");
    free(logs);
    return send_json(req, resp);
}

/* ── Captive portal: redirect unknown paths to / ──────── */

static esp_err_t captive_redirect_handler(httpd_req_t *req, httpd_err_code_t err)
{
    httpd_resp_set_status(req, "302 Temporary Redirect");
    httpd_resp_set_hdr(req, "Location", "/");
    /* iOS requires body to detect captive portal */
    httpd_resp_send(req, "Redirect to captive portal", HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

/* ── Server startup ───────────────────────────────────── */

static void register_uri(httpd_handle_t server, httpd_method_t method,
                         const char *uri, esp_err_t (*handler)(httpd_req_t *))
{
    httpd_uri_t u = { .uri = uri, .method = method, .handler = handler };
    httpd_register_uri_handler(server, &u);
}

static void session_close_fn(httpd_handle_t hd, int sockfd)
{
    ws_remove_client(sockfd);
    close(sockfd);
}

esp_err_t web_server_start(void)
{
    auth_load_password();

    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.max_uri_handlers = 25;
    config.stack_size = 8192;
    config.lru_purge_enable = true;
    config.close_fn = session_close_fn;

    esp_err_t err = httpd_start(&s_server, &config);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to start HTTP server: 0x%x", err);
        return err;
    }

    /* WebSocket endpoint */
    ws_init(s_server);

    register_uri(s_server, HTTP_GET,  "/",                   handler_index);
    register_uri(s_server, HTTP_GET,  "/blockly.js",         handler_blockly_js);
    register_uri(s_server, HTTP_GET,  "/api/status",         handler_status);
    register_uri(s_server, HTTP_GET,  "/api/devices",        handler_devices);
    register_uri(s_server, HTTP_GET,  "/api/logs",           handler_logs);
    register_uri(s_server, HTTP_GET,  "/api/defs",           handler_defs_get);
    register_uri(s_server, HTTP_POST, "/api/defs",           handler_defs_post);
    register_uri(s_server, HTTP_POST, "/api/permit_join",    handler_permit_join);
    register_uri(s_server, HTTP_POST, "/api/device/cmd",     handler_device_cmd);
    register_uri(s_server, HTTP_POST, "/api/device/rename",  handler_device_rename);
    register_uri(s_server, HTTP_POST, "/api/device/remove",  handler_device_remove);
    register_uri(s_server, HTTP_POST, "/api/settings/wifi",    handler_wifi_settings);
    register_uri(s_server, HTTP_POST, "/api/settings/zigbee", handler_zigbee_settings);
    register_uri(s_server, HTTP_POST, "/api/settings/password", handler_password);
    register_uri(s_server, HTTP_POST, "/api/system/restart",  handler_restart);
    register_uri(s_server, HTTP_POST, "/api/system/factory-reset", handler_factory_reset);
    /* RCP reflash removed — NCP has its own USB port for flashing */
    register_uri(s_server, HTTP_POST, "/api/ota",             handler_ota);

    /* Automation */
    register_uri(s_server, HTTP_GET,  "/api/automations",        handler_automations_get);
    register_uri(s_server, HTTP_POST, "/api/automations",        handler_automations_save);
    register_uri(s_server, HTTP_POST, "/api/automations/delete", handler_automations_delete);
    register_uri(s_server, HTTP_POST, "/api/automations/toggle", handler_automations_toggle);
    register_uri(s_server, HTTP_POST, "/api/automations/run",    handler_automations_run);

    /* Captive portal: redirect any 404 to root page */
    httpd_register_err_handler(s_server, HTTPD_404_NOT_FOUND, captive_redirect_handler);

    ESP_LOGI(TAG, "HTTP server started (WebSocket enabled)");
    return ESP_OK;
}

void web_server_stop(void)
{
    if (s_server) {
        httpd_stop(s_server);
        s_server = NULL;
    }
}
