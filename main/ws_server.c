#include "ws_server.h"
#include "wifi.h"
#include "zigbee.h"
#include "device_list.h"

#include <string.h>
#include <stdlib.h>
#include "esp_log.h"
#include "esp_http_server.h"
#include "esp_timer.h"
#include "esp_system.h"
#include "cJSON.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "ws";

extern const char *FW_VERSION;

/* ── Client tracking ─────────────────────────────────── */

#define WS_MAX_CLIENTS 4
static httpd_handle_t s_hd;
static int s_ws_fds[WS_MAX_CLIENTS]; /* -1 = unused */

/* ── Log batching ────────────────────────────────────── */

#define WS_LOG_BUF_SIZE 2048
static char s_ws_log_buf[WS_LOG_BUF_SIZE];
static size_t s_ws_log_len;
static portMUX_TYPE s_ws_log_mux = portMUX_INITIALIZER_UNLOCKED;
static esp_timer_handle_t s_log_timer;

/* ── Helpers ─────────────────────────────────────────── */

static bool ws_has_clients(void)
{
    for (int i = 0; i < WS_MAX_CLIENTS; i++) {
        if (s_ws_fds[i] >= 0) return true;
    }
    return false;
}

static void ws_broadcast(const char *data, size_t len)
{
    httpd_ws_frame_t frame = {
        .final = true,
        .type = HTTPD_WS_TYPE_TEXT,
        .payload = (uint8_t *)data,
        .len = len,
    };

    for (int i = 0; i < WS_MAX_CLIENTS; i++) {
        if (s_ws_fds[i] < 0) continue;

        if (httpd_ws_get_fd_info(s_hd, s_ws_fds[i]) != HTTPD_WS_CLIENT_WEBSOCKET) {
            s_ws_fds[i] = -1;
            continue;
        }

        esp_err_t ret = httpd_ws_send_frame_async(s_hd, s_ws_fds[i], &frame);
        if (ret != ESP_OK) {
            ESP_LOGW(TAG, "WS send failed fd=%d: %s", s_ws_fds[i], esp_err_to_name(ret));
            httpd_sess_trigger_close(s_hd, s_ws_fds[i]);
            s_ws_fds[i] = -1;
        }
    }
}

/* ── JSON builders (shared with HTTP handlers) ───────── */

static void ieee_to_str(const esp_zb_ieee_addr_t addr, char *out, size_t out_size)
{
    snprintf(out, out_size, "%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X",
             addr[7], addr[6], addr[5], addr[4],
             addr[3], addr[2], addr[1], addr[0]);
}

cJSON *ws_build_status_json(void)
{
    cJSON *root = cJSON_CreateObject();
    if (!root) return NULL;

    /* WiFi */
    wifi_status_t ws;
    wifi_get_status(&ws);
    cJSON *wifi = cJSON_AddObjectToObject(root, "wifi");
    cJSON_AddStringToObject(wifi, "state",
        ws.state == WIFI_STATE_CONNECTED ? "connected" :
        ws.state == WIFI_STATE_AP_ACTIVE ? "ap" :
        ws.state == WIFI_STATE_CONNECTING ? "connecting" : "idle");
    cJSON_AddStringToObject(wifi, "ssid", ws.ssid);
    cJSON_AddStringToObject(wifi, "ip", ws.ip);
    cJSON_AddNumberToObject(wifi, "rssi", ws.rssi);

    /* Zigbee */
    zigbee_status_t zs;
    zigbee_get_status(&zs);
    cJSON *zb = cJSON_AddObjectToObject(root, "zigbee");
    cJSON_AddBoolToObject(zb, "running", zs.running);
    cJSON_AddNumberToObject(zb, "channel", zs.channel);
    char pan[8];
    snprintf(pan, sizeof(pan), "0x%04X", zs.pan_id);
    cJSON_AddStringToObject(zb, "pan_id", pan);
    cJSON_AddNumberToObject(zb, "devices", zs.device_count);
    cJSON_AddBoolToObject(zb, "permit_join", zs.permit_join);
    cJSON_AddNumberToObject(zb, "permit_join_remaining", zs.permit_join_remaining);

    /* System */
    cJSON *sys = cJSON_AddObjectToObject(root, "system");
    int64_t uptime = esp_timer_get_time() / 1000000;
    cJSON_AddNumberToObject(sys, "uptime", uptime);
    cJSON_AddNumberToObject(sys, "heap", esp_get_free_heap_size());
    cJSON_AddStringToObject(sys, "firmware", FW_VERSION);

    return root;
}

cJSON *ws_build_device_json(const zb_device_t *d)
{
    cJSON *obj = cJSON_CreateObject();
    if (!obj) return NULL;
    char addr_str[8];
    snprintf(addr_str, sizeof(addr_str), "0x%04X", d->short_addr);
    cJSON_AddStringToObject(obj, "addr", addr_str);

    char ieee_str[24];
    ieee_to_str(d->ieee_addr, ieee_str, sizeof(ieee_str));
    cJSON_AddStringToObject(obj, "ieee", ieee_str);
    cJSON_AddStringToObject(obj, "name", d->name);
    cJSON_AddStringToObject(obj, "manufacturer", d->manufacturer);
    cJSON_AddStringToObject(obj, "model", d->model);
    cJSON_AddNumberToObject(obj, "lqi", d->lqi);
    cJSON_AddBoolToObject(obj, "discovery_done", d->discovery_done);
    if (d->has_battery) {
        cJSON_AddNumberToObject(obj, "battery_mv", d->battery_mv);
        /* Rough percentage: 3100mV=100%, 2700mV=0% for CR2032 */
        int pct = (d->battery_mv - 2700) * 100 / 400;
        if (pct > 100) pct = 100;
        if (pct < 0) pct = 0;
        cJSON_AddNumberToObject(obj, "battery_pct", pct);
        cJSON_AddNumberToObject(obj, "device_temp", d->device_temp);
    }

    int64_t now = esp_timer_get_time() / 1000000;
    int64_t ago = d->last_seen_sec > 0 ? now - d->last_seen_sec : -1;
    cJSON_AddNumberToObject(obj, "last_seen_sec_ago", ago);

    /* Endpoints */
    cJSON *eps = cJSON_AddArrayToObject(obj, "endpoints");
    for (int e = 0; e < d->ep_count; e++) {
        const dev_endpoint_t *ep = &d->endpoints[e];
        cJSON *epj = cJSON_CreateObject();
        cJSON_AddNumberToObject(epj, "id", ep->id);

        char dev_id[8];
        snprintf(dev_id, sizeof(dev_id), "0x%04X", ep->device_id);
        cJSON_AddStringToObject(epj, "device_id", dev_id);

        if (ep->has_on_off)      cJSON_AddBoolToObject(epj, "on_off", ep->on_off_state);
        if (ep->has_level)       cJSON_AddNumberToObject(epj, "level", ep->level);
        if (ep->has_temperature) cJSON_AddNumberToObject(epj, "temperature", ep->temperature / 100.0);
        if (ep->has_humidity)    cJSON_AddNumberToObject(epj, "humidity", ep->humidity / 100.0);
        if (ep->has_pressure)    cJSON_AddNumberToObject(epj, "pressure", ep->pressure);
        if (ep->has_illuminance) cJSON_AddNumberToObject(epj, "illuminance", ep->illuminance);
        if (ep->has_occupancy)   cJSON_AddBoolToObject(epj, "occupancy", ep->occupancy != 0);

        cJSON_AddItemToArray(eps, epj);
    }

    return obj;
}

cJSON *ws_build_devices_json(void)
{
    cJSON *arr = cJSON_CreateArray();
    if (!arr) return NULL;

    device_lock();
    zb_device_t *all = device_get_all();
    for (int i = 0; i < MAX_DEVICES; i++) {
        if (!all[i].in_use) continue;
        cJSON_AddItemToArray(arr, ws_build_device_json(&all[i]));
    }
    device_unlock();

    return arr;
}

/* ── Event types ─────────────────────────────────────── */

typedef enum {
    WS_EVT_STATUS,
    WS_EVT_DEVICES,
    WS_EVT_DEVICE_UPDATE,
    WS_EVT_DEVICE_REMOVE,
    WS_EVT_PERMIT_JOIN,
    WS_EVT_INITIAL_SYNC,
} ws_evt_type_t;

typedef struct {
    ws_evt_type_t type;
    uint16_t short_addr;
    bool     pj_active;
    uint8_t  pj_remaining;
} ws_work_t;

/* ── Push function (runs in HTTPD context) ───────────── */

static void ws_push_fn(void *arg)
{
    ws_work_t *w = (ws_work_t *)arg;
    if (!ws_has_clients()) { free(w); return; }

    char *json_str = NULL;

    switch (w->type) {
    case WS_EVT_STATUS: {
        cJSON *root = cJSON_CreateObject();
        cJSON_AddStringToObject(root, "type", "status");
        cJSON_AddItemToObject(root, "data", ws_build_status_json());
        json_str = cJSON_PrintUnformatted(root);
        cJSON_Delete(root);
        break;
    }
    case WS_EVT_DEVICES: {
        cJSON *root = cJSON_CreateObject();
        cJSON_AddStringToObject(root, "type", "devices");
        cJSON_AddItemToObject(root, "data", ws_build_devices_json());
        json_str = cJSON_PrintUnformatted(root);
        cJSON_Delete(root);
        break;
    }
    case WS_EVT_DEVICE_UPDATE: {
        device_lock();
        int idx = device_find(w->short_addr);
        if (idx >= 0) {
            cJSON *root = cJSON_CreateObject();
            cJSON_AddStringToObject(root, "type", "device_update");
            cJSON_AddItemToObject(root, "data", ws_build_device_json(device_get(idx)));
            json_str = cJSON_PrintUnformatted(root);
            cJSON_Delete(root);
        }
        device_unlock();
        break;
    }
    case WS_EVT_DEVICE_REMOVE: {
        cJSON *root = cJSON_CreateObject();
        cJSON_AddStringToObject(root, "type", "device_remove");
        cJSON *data = cJSON_AddObjectToObject(root, "data");
        char addr_str[8];
        snprintf(addr_str, sizeof(addr_str), "0x%04X", w->short_addr);
        cJSON_AddStringToObject(data, "addr", addr_str);
        json_str = cJSON_PrintUnformatted(root);
        cJSON_Delete(root);
        break;
    }
    case WS_EVT_PERMIT_JOIN: {
        cJSON *root = cJSON_CreateObject();
        cJSON_AddStringToObject(root, "type", "permit_join");
        cJSON *data = cJSON_AddObjectToObject(root, "data");
        cJSON_AddBoolToObject(data, "active", w->pj_active);
        cJSON_AddNumberToObject(data, "remaining", w->pj_remaining);
        json_str = cJSON_PrintUnformatted(root);
        cJSON_Delete(root);
        break;
    }
    case WS_EVT_INITIAL_SYNC: {
        /* Send status */
        cJSON *root = cJSON_CreateObject();
        cJSON_AddStringToObject(root, "type", "status");
        cJSON_AddItemToObject(root, "data", ws_build_status_json());
        char *str = cJSON_PrintUnformatted(root);
        cJSON_Delete(root);
        if (str) { ws_broadcast(str, strlen(str)); free(str); }

        /* Send devices */
        root = cJSON_CreateObject();
        cJSON_AddStringToObject(root, "type", "devices");
        cJSON_AddItemToObject(root, "data", ws_build_devices_json());
        str = cJSON_PrintUnformatted(root);
        cJSON_Delete(root);
        if (str) { ws_broadcast(str, strlen(str)); free(str); }

        free(w);
        return;
    }
    }

    if (json_str) {
        ws_broadcast(json_str, strlen(json_str));
        free(json_str);
    }
    free(w);
}

/* ── Log flush (runs in HTTPD context) ───────────────── */

static void ws_log_flush_fn(void *arg)
{
    char *text = (char *)arg;
    if (!ws_has_clients()) { free(text); return; }

    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "type", "log");
    cJSON_AddStringToObject(root, "data", text);
    char *json_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    free(text);

    if (json_str) {
        ws_broadcast(json_str, strlen(json_str));
        free(json_str);
    }
}

static void log_timer_cb(void *arg)
{
    (void)arg;

    /* Snapshot length under spinlock, then malloc outside it */
    portENTER_CRITICAL(&s_ws_log_mux);
    size_t len = s_ws_log_len;
    portEXIT_CRITICAL(&s_ws_log_mux);

    if (len == 0) return;

    char *copy = malloc(len + 1);
    if (!copy) return;

    portENTER_CRITICAL(&s_ws_log_mux);
    /* Buffer may have grown — only copy what we allocated for */
    if (s_ws_log_len <= len) {
        len = s_ws_log_len;
        memcpy(copy, s_ws_log_buf, len);
        s_ws_log_len = 0;
    } else {
        memcpy(copy, s_ws_log_buf, len);
        memmove(s_ws_log_buf, s_ws_log_buf + len, s_ws_log_len - len);
        s_ws_log_len -= len;
    }
    portEXIT_CRITICAL(&s_ws_log_mux);
    copy[len] = '\0';

    if (len > 0 && s_hd) {
        if (httpd_queue_work(s_hd, ws_log_flush_fn, copy) != ESP_OK) {
            free(copy);
        }
    } else {
        free(copy);
    }
}

/* ── WebSocket handler ───────────────────────────────── */

static esp_err_t ws_handler(httpd_req_t *req)
{
    if (req->method == HTTP_GET) {
        /* Handshake complete — store client fd */
        int fd = httpd_req_to_sockfd(req);
        ESP_LOGI(TAG, "WS client connected: fd=%d", fd);

        bool stored = false;
        for (int i = 0; i < WS_MAX_CLIENTS; i++) {
            if (s_ws_fds[i] < 0) {
                s_ws_fds[i] = fd;
                stored = true;
                break;
            }
        }
        if (!stored) {
            ESP_LOGW(TAG, "WS client array full, rejecting fd=%d", fd);
            return ESP_ERR_NO_MEM;
        }

        /* Queue initial sync (runs after handshake response is sent) */
        ws_work_t *w = calloc(1, sizeof(ws_work_t));
        if (w) {
            w->type = WS_EVT_INITIAL_SYNC;
            if (httpd_queue_work(s_hd, ws_push_fn, w) != ESP_OK) free(w);
        }
        return ESP_OK;
    }

    /* Receive and discard data frames */
    httpd_ws_frame_t frame = { .type = HTTPD_WS_TYPE_TEXT };
    esp_err_t ret = httpd_ws_recv_frame(req, &frame, 0);
    if (ret != ESP_OK) return ret;

    if (frame.len > 0) {
        uint8_t *buf = malloc(frame.len);
        if (buf) {
            frame.payload = buf;
            ret = httpd_ws_recv_frame(req, &frame, frame.len);
            if (ret != ESP_OK) {
                ESP_LOGW(TAG, "WS recv payload failed: %s", esp_err_to_name(ret));
            }
            free(buf);
        }
    }
    return ESP_OK;
}

/* ── Public API ──────────────────────────────────────── */

void ws_remove_client(int fd)
{
    for (int i = 0; i < WS_MAX_CLIENTS; i++) {
        if (s_ws_fds[i] == fd) {
            s_ws_fds[i] = -1;
            ESP_LOGI(TAG, "WS client removed: fd=%d", fd);
            return;
        }
    }
}

void ws_init(httpd_handle_t server)
{
    s_hd = server;
    for (int i = 0; i < WS_MAX_CLIENTS; i++) s_ws_fds[i] = -1;

    static const httpd_uri_t ws_uri = {
        .uri = "/ws",
        .method = HTTP_GET,
        .handler = ws_handler,
        .is_websocket = true,
    };
    esp_err_t err = httpd_register_uri_handler(server, &ws_uri);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to register /ws handler: %s", esp_err_to_name(err));
    }

    /* Start log flush timer */
    const esp_timer_create_args_t timer_args = {
        .callback = log_timer_cb,
        .name = "ws_log",
    };
    err = esp_timer_create(&timer_args, &s_log_timer);
    if (err == ESP_OK) {
        esp_timer_start_periodic(s_log_timer, 500000); /* 500ms */
    } else {
        ESP_LOGE(TAG, "Failed to create WS log timer: %s", esp_err_to_name(err));
    }

    ESP_LOGI(TAG, "WebSocket server initialized");
}

void ws_notify_status(void)
{
    if (!s_hd) return;
    ws_work_t *w = calloc(1, sizeof(ws_work_t));
    if (!w) return;
    w->type = WS_EVT_STATUS;
    if (httpd_queue_work(s_hd, ws_push_fn, w) != ESP_OK) free(w);
}

void ws_notify_devices(void)
{
    if (!s_hd) return;
    ws_work_t *w = calloc(1, sizeof(ws_work_t));
    if (!w) return;
    w->type = WS_EVT_DEVICES;
    if (httpd_queue_work(s_hd, ws_push_fn, w) != ESP_OK) free(w);
}

void ws_notify_device_update(uint16_t short_addr)
{
    if (!s_hd) return;
    ws_work_t *w = calloc(1, sizeof(ws_work_t));
    if (!w) return;
    w->type = WS_EVT_DEVICE_UPDATE;
    w->short_addr = short_addr;
    if (httpd_queue_work(s_hd, ws_push_fn, w) != ESP_OK) free(w);
}

void ws_notify_device_remove(uint16_t short_addr)
{
    if (!s_hd) return;
    ws_work_t *w = calloc(1, sizeof(ws_work_t));
    if (!w) return;
    w->type = WS_EVT_DEVICE_REMOVE;
    w->short_addr = short_addr;
    if (httpd_queue_work(s_hd, ws_push_fn, w) != ESP_OK) free(w);
}

void ws_notify_permit_join(bool active, uint8_t remaining)
{
    if (!s_hd) return;
    ws_work_t *w = calloc(1, sizeof(ws_work_t));
    if (!w) return;
    w->type = WS_EVT_PERMIT_JOIN;
    w->pj_active = active;
    w->pj_remaining = remaining;
    if (httpd_queue_work(s_hd, ws_push_fn, w) != ESP_OK) free(w);
}

void ws_notify_log(const char *text, int len)
{
    if (!s_hd || len <= 0) return;
    portENTER_CRITICAL_SAFE(&s_ws_log_mux);
    int avail = WS_LOG_BUF_SIZE - (int)s_ws_log_len;
    if (len > avail) len = avail;
    if (len > 0) {
        memcpy(s_ws_log_buf + s_ws_log_len, text, len);
        s_ws_log_len += len;
    }
    portEXIT_CRITICAL_SAFE(&s_ws_log_mux);
}
