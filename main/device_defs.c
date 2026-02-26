#include "device_defs.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "esp_log.h"
#include "esp_spiffs.h"
#include "cJSON.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

static const char *TAG = "devdefs";
static const char *DEFS_PATH = "/rcp_fw/devices.json";

static device_def_t s_defs[MAX_DEVICE_DEFS];
static int s_def_count;
static SemaphoreHandle_t s_defs_mutex;

/* ── SPIFFS mount (idempotent) ────────────────────────── */

static void ensure_spiffs(void)
{
    if (esp_spiffs_mounted("rcp_fw")) return;

    esp_vfs_spiffs_conf_t conf = {
        .base_path = "/rcp_fw",
        .partition_label = "rcp_fw",
        .max_files = 10,
        .format_if_mount_failed = true,
    };
    esp_err_t err = esp_vfs_spiffs_register(&conf);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "SPIFFS mount failed: 0x%x", err);
    }
}

/* ── Load + parse ─────────────────────────────────────── */

/* Internal load — caller must hold s_defs_mutex (or be in init before mutex exists) */
static void device_defs_load_locked(void)
{
    s_def_count = 0;

    FILE *f = fopen(DEFS_PATH, "r");
    if (!f) {
        ESP_LOGI(TAG, "No %s — no device definitions loaded", DEFS_PATH);
        return;
    }

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (sz <= 0 || sz > 8192) {
        ESP_LOGW(TAG, "devices.json size %ld invalid", sz);
        fclose(f);
        return;
    }

    char *buf = malloc(sz + 1);
    if (!buf) { fclose(f); return; }

    size_t nread = fread(buf, 1, sz, f);
    fclose(f);
    if (nread == 0) {
        ESP_LOGW(TAG, "devices.json read returned 0 bytes");
        free(buf);
        return;
    }
    buf[nread] = '\0';

    cJSON *root = cJSON_Parse(buf);
    free(buf);
    if (!root) {
        ESP_LOGW(TAG, "devices.json parse failed");
        return;
    }

    /* Iterate: manufacturer -> model -> bind -> endpoint -> clusters */
    cJSON *mfr_obj;
    cJSON_ArrayForEach(mfr_obj, root) {
        const char *mfr_name = mfr_obj->string;
        if (!mfr_name || !cJSON_IsObject(mfr_obj)) continue;

        cJSON *model_obj;
        cJSON_ArrayForEach(model_obj, mfr_obj) {
            if (s_def_count >= MAX_DEVICE_DEFS) break;
            const char *model_name = model_obj->string;
            if (!model_name || !cJSON_IsObject(model_obj)) continue;

            device_def_t *def = &s_defs[s_def_count];
            memset(def, 0, sizeof(*def));
            strncpy(def->manufacturer, mfr_name, sizeof(def->manufacturer) - 1);
            strncpy(def->model, model_name, sizeof(def->model) - 1);

            cJSON *bind_obj = cJSON_GetObjectItem(model_obj, "bind");
            if (bind_obj && cJSON_IsObject(bind_obj)) {
                cJSON *ep_obj;
                cJSON_ArrayForEach(ep_obj, bind_obj) {
                    if (def->bind_count >= MAX_BIND_EPS) break;
                    if (!ep_obj->string || !cJSON_IsArray(ep_obj)) continue;

                    dev_def_bind_t *b = &def->binds[def->bind_count];
                    b->endpoint = (uint8_t)atoi(ep_obj->string);
                    b->cluster_count = 0;

                    cJSON *cl_item;
                    cJSON_ArrayForEach(cl_item, ep_obj) {
                        if (b->cluster_count >= MAX_BIND_CLUSTERS) break;
                        if (cJSON_IsString(cl_item)) {
                            b->clusters[b->cluster_count++] =
                                (uint16_t)strtol(cl_item->valuestring, NULL, 16);
                        }
                    }
                    if (b->cluster_count > 0) def->bind_count++;
                }
            }

            ESP_LOGI(TAG, "Def: %s / %s (%d bind groups)",
                     def->manufacturer, def->model, def->bind_count);
            s_def_count++;
        }
        if (s_def_count >= MAX_DEVICE_DEFS) break;
    }

    cJSON_Delete(root);
    ESP_LOGI(TAG, "Loaded %d device definitions", s_def_count);
}

/* ── Init ─────────────────────────────────────────────── */

void device_defs_load(void)
{
    xSemaphoreTake(s_defs_mutex, portMAX_DELAY);
    device_defs_load_locked();
    xSemaphoreGive(s_defs_mutex);
}

void device_defs_init(void)
{
    s_defs_mutex = xSemaphoreCreateMutex();
    assert(s_defs_mutex);
    ensure_spiffs();
    device_defs_load_locked();  /* mutex not needed yet, no other tasks */
}

/* ── Find ─────────────────────────────────────────────── */

const device_def_t *device_defs_find(const char *manufacturer, const char *model)
{
    if (!manufacturer || !model) return NULL;
    xSemaphoreTake(s_defs_mutex, portMAX_DELAY);
    const device_def_t *result = NULL;
    for (int i = 0; i < s_def_count; i++) {
        if (strcmp(s_defs[i].manufacturer, manufacturer) == 0 &&
            strcmp(s_defs[i].model, model) == 0) {
            result = &s_defs[i];
            break;
        }
    }
    xSemaphoreGive(s_defs_mutex);
    return result;
}

/* ── Save ─────────────────────────────────────────────── */

int device_defs_save(const char *json_str, size_t len)
{
    /* Validate JSON first */
    cJSON *test = cJSON_Parse(json_str);
    if (!test) {
        ESP_LOGW(TAG, "Invalid JSON, not saving");
        return -1;
    }
    cJSON_Delete(test);

    ensure_spiffs();

    FILE *f = fopen(DEFS_PATH, "w");
    if (!f) {
        ESP_LOGE(TAG, "Cannot open %s for writing", DEFS_PATH);
        return -1;
    }

    size_t written = fwrite(json_str, 1, len, f);
    fclose(f);

    if (written != len) {
        ESP_LOGE(TAG, "Write incomplete: %d/%d", (int)written, (int)len);
        return -1;
    }

    ESP_LOGI(TAG, "Saved %d bytes to %s", (int)len, DEFS_PATH);
    xSemaphoreTake(s_defs_mutex, portMAX_DELAY);
    device_defs_load_locked();
    xSemaphoreGive(s_defs_mutex);
    return 0;
}

/* ── Get JSON ─────────────────────────────────────────── */

char *device_defs_get_json(void)
{
    ensure_spiffs();

    FILE *f = fopen(DEFS_PATH, "r");
    if (!f) return NULL;

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (sz <= 0 || sz > 8192) {
        fclose(f);
        return NULL;
    }

    char *buf = malloc(sz + 1);
    if (!buf) { fclose(f); return NULL; }

    size_t nread = fread(buf, 1, sz, f);
    fclose(f);
    if (nread == 0) {
        free(buf);
        return NULL;
    }
    buf[nread] = '\0';
    return buf;
}
