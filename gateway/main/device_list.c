#include "device_list.h"

#include <string.h>
#include "esp_log.h"
#include "esp_timer.h"
#include "nvs_flash.h"
#include "nvs.h"

static const char *TAG = "devlist";

/* ── Deferred save ────────────────────────────────────── */

static volatile bool s_save_pending;
static esp_timer_handle_t s_save_timer;

/* ── NVS persistence format (packed) ──────────────────── */

#define DEV_NVS_MAGIC    0x5A42   /* "ZB" */
#define DEV_NVS_VERSION  2
#define DEV_NVS_NS       "dev_list"
#define DEV_NVS_KEY      "devices"
#define NVS_MFR_LEN      16
#define NVS_MODEL_LEN    16

typedef struct __attribute__((packed)) {
    uint8_t  id;
    uint16_t device_id;
    uint8_t  flags;    /* bit0=on_off, 1=level, 2=temp, 3=hum, 4=press, 5=illum, 6=occupancy */
} dev_ep_nvs_t;

typedef struct __attribute__((packed)) {
    uint16_t short_addr;
    uint8_t  ieee_addr[8];
    char     name[DEV_NAME_LEN];
    char     manufacturer[NVS_MFR_LEN];
    char     model[NVS_MODEL_LEN];
    uint8_t  ep_count;
    dev_ep_nvs_t eps[MAX_EP_PER_DEV];
} dev_nvs_record_t;

typedef struct __attribute__((packed)) {
    uint16_t magic;
    uint8_t  version;
    uint8_t  count;
} dev_nvs_header_t;

static zb_device_t  s_devices[MAX_DEVICES];
static SemaphoreHandle_t s_mutex;

void device_list_init(void)
{
    memset(s_devices, 0, sizeof(s_devices));
    s_mutex = xSemaphoreCreateMutex();
    assert(s_mutex);
    device_list_load();
}

void device_lock(void)
{
    xSemaphoreTake(s_mutex, portMAX_DELAY);
}

void device_unlock(void)
{
    xSemaphoreGive(s_mutex);
}

int device_add(uint16_t short_addr, const esp_zb_ieee_addr_t ieee_addr)
{
    device_lock();

    /* Check if already known by short address */
    for (int i = 0; i < MAX_DEVICES; i++) {
        if (s_devices[i].in_use && s_devices[i].short_addr == short_addr) {
            memcpy(s_devices[i].ieee_addr, ieee_addr, sizeof(esp_zb_ieee_addr_t));
            s_devices[i].last_seen_sec = esp_timer_get_time() / 1000000;
            ESP_LOGI(TAG, "Device 0x%04X re-announced (same addr, \"%s\")", short_addr, s_devices[i].name);
            device_unlock();
            device_list_save_deferred();
            return i;
        }
    }

    /* Check by IEEE — same device, new short address (re-joined) */
    for (int i = 0; i < MAX_DEVICES; i++) {
        if (s_devices[i].in_use &&
            memcmp(s_devices[i].ieee_addr, ieee_addr, sizeof(esp_zb_ieee_addr_t)) == 0) {
            uint16_t old_addr = s_devices[i].short_addr;
            s_devices[i].short_addr = short_addr;
            s_devices[i].last_seen_sec = esp_timer_get_time() / 1000000;
            s_devices[i].discovery_done = false;
            ESP_LOGI(TAG, "Device re-joined: 0x%04X -> 0x%04X (\"%s\")", old_addr, short_addr, s_devices[i].name);
            device_unlock();
            device_list_save_deferred();
            return i;
        }
    }

    /* Find free slot */
    for (int i = 0; i < MAX_DEVICES; i++) {
        if (!s_devices[i].in_use) {
            memset(&s_devices[i], 0, sizeof(zb_device_t));
            s_devices[i].in_use = true;
            s_devices[i].short_addr = short_addr;
            memcpy(s_devices[i].ieee_addr, ieee_addr, sizeof(esp_zb_ieee_addr_t));
            s_devices[i].last_seen_sec = esp_timer_get_time() / 1000000;
            snprintf(s_devices[i].name, DEV_NAME_LEN, "Device 0x%04X", short_addr);
            device_unlock();
            ESP_LOGI(TAG, "Added device 0x%04X (slot %d)", short_addr, i);
            return i;
        }
    }

    device_unlock();
    ESP_LOGW(TAG, "Device list full, cannot add 0x%04X", short_addr);
    return -1;
}

int device_find(uint16_t short_addr)
{
    for (int i = 0; i < MAX_DEVICES; i++) {
        if (s_devices[i].in_use && s_devices[i].short_addr == short_addr) {
            return i;
        }
    }
    return -1;
}

int device_find_by_ieee(const esp_zb_ieee_addr_t ieee_addr)
{
    for (int i = 0; i < MAX_DEVICES; i++) {
        if (s_devices[i].in_use &&
            memcmp(s_devices[i].ieee_addr, ieee_addr, sizeof(esp_zb_ieee_addr_t)) == 0) {
            return i;
        }
    }
    return -1;
}

void device_remove(int idx)
{
    if (idx >= 0 && idx < MAX_DEVICES) {
        s_devices[idx].in_use = false;
    }
}

int device_count(void)
{
    int cnt = 0;
    for (int i = 0; i < MAX_DEVICES; i++) {
        if (s_devices[i].in_use) cnt++;
    }
    return cnt;
}

zb_device_t *device_get(int idx)
{
    if (idx >= 0 && idx < MAX_DEVICES && s_devices[idx].in_use) {
        return &s_devices[idx];
    }
    return NULL;
}

zb_device_t *device_get_all(void)
{
    return s_devices;
}

/* ── NVS persistence ──────────────────────────────────── */

void device_list_save(void)
{
    device_lock();

    /* Count active devices */
    uint8_t count = 0;
    for (int i = 0; i < MAX_DEVICES; i++) {
        if (s_devices[i].in_use && s_devices[i].discovery_done) count++;
    }

    size_t buf_size = sizeof(dev_nvs_header_t) + count * sizeof(dev_nvs_record_t);
    if (buf_size > 3072) {  /* NVS blob limit is ~4000 bytes for one page */
        ESP_LOGW(TAG, "NVS blob size %d approaching limit!", (int)buf_size);
    }
    uint8_t *buf = malloc(buf_size);
    if (!buf) {
        device_unlock();
        ESP_LOGE(TAG, "NVS save: alloc failed");
        return;
    }

    dev_nvs_header_t *hdr = (dev_nvs_header_t *)buf;
    hdr->magic   = DEV_NVS_MAGIC;
    hdr->version = DEV_NVS_VERSION;
    hdr->count   = count;

    dev_nvs_record_t *recs = (dev_nvs_record_t *)(buf + sizeof(dev_nvs_header_t));
    int ri = 0;
    for (int i = 0; i < MAX_DEVICES && ri < count; i++) {
        if (!s_devices[i].in_use || !s_devices[i].discovery_done) continue;
        zb_device_t *d = &s_devices[i];
        dev_nvs_record_t *r = &recs[ri++];

        r->short_addr = d->short_addr;
        memcpy(r->ieee_addr, d->ieee_addr, 8);
        memcpy(r->name, d->name, DEV_NAME_LEN);
        memset(r->manufacturer, 0, NVS_MFR_LEN);
        strncpy(r->manufacturer, d->manufacturer, NVS_MFR_LEN - 1);
        memset(r->model, 0, NVS_MODEL_LEN);
        strncpy(r->model, d->model, NVS_MODEL_LEN - 1);
        r->ep_count = d->ep_count > MAX_EP_PER_DEV ? MAX_EP_PER_DEV : d->ep_count;

        for (int e = 0; e < r->ep_count; e++) {
            dev_endpoint_t *ep = &d->endpoints[e];
            r->eps[e].id = ep->id;
            r->eps[e].device_id = ep->device_id;
            r->eps[e].flags = (ep->has_on_off ? 0x01 : 0)
                            | (ep->has_level ? 0x02 : 0)
                            | (ep->has_temperature ? 0x04 : 0)
                            | (ep->has_humidity ? 0x08 : 0)
                            | (ep->has_pressure ? 0x10 : 0)
                            | (ep->has_illuminance ? 0x20 : 0)
                            | (ep->has_occupancy ? 0x40 : 0);
        }
        /* Zero unused endpoint slots */
        for (int e = r->ep_count; e < MAX_EP_PER_DEV; e++) {
            memset(&r->eps[e], 0, sizeof(dev_ep_nvs_t));
        }
    }

    device_unlock();

    nvs_handle_t nvs;
    esp_err_t err = nvs_open(DEV_NVS_NS, NVS_READWRITE, &nvs);
    if (err == ESP_OK) {
        err = nvs_set_blob(nvs, DEV_NVS_KEY, buf, buf_size);
        if (err == ESP_OK) {
            nvs_commit(nvs);
            ESP_LOGI(TAG, "Saved %d devices to NVS (%d bytes)", count, (int)buf_size);
        } else {
            ESP_LOGE(TAG, "NVS set_blob failed: %s", esp_err_to_name(err));
        }
        nvs_close(nvs);
    } else {
        ESP_LOGE(TAG, "NVS open failed: %s", esp_err_to_name(err));
    }

    free(buf);
}

void device_list_load(void)
{
    nvs_handle_t nvs;
    esp_err_t err = nvs_open(DEV_NVS_NS, NVS_READONLY, &nvs);
    if (err != ESP_OK) return;  /* No saved data — that's fine */

    size_t blob_size = 0;
    err = nvs_get_blob(nvs, DEV_NVS_KEY, NULL, &blob_size);
    if (err != ESP_OK || blob_size < sizeof(dev_nvs_header_t)) {
        nvs_close(nvs);
        return;
    }

    uint8_t *buf = malloc(blob_size);
    if (!buf) { nvs_close(nvs); return; }

    err = nvs_get_blob(nvs, DEV_NVS_KEY, buf, &blob_size);
    nvs_close(nvs);
    if (err != ESP_OK) { free(buf); return; }

    dev_nvs_header_t *hdr = (dev_nvs_header_t *)buf;
    if (hdr->magic != DEV_NVS_MAGIC || hdr->version != DEV_NVS_VERSION) {
        ESP_LOGW(TAG, "NVS device data: bad magic/version, ignoring");
        free(buf);
        return;
    }

    size_t expected = sizeof(dev_nvs_header_t) + hdr->count * sizeof(dev_nvs_record_t);
    if (blob_size < expected || hdr->count > MAX_DEVICES) {
        ESP_LOGW(TAG, "NVS device data: size mismatch, ignoring");
        free(buf);
        return;
    }

    dev_nvs_record_t *recs = (dev_nvs_record_t *)(buf + sizeof(dev_nvs_header_t));

    device_lock();
    for (int i = 0; i < hdr->count; i++) {
        dev_nvs_record_t *r = &recs[i];

        /* Find a free slot */
        int slot = -1;
        for (int j = 0; j < MAX_DEVICES; j++) {
            if (!s_devices[j].in_use) { slot = j; break; }
        }
        if (slot < 0) break;

        zb_device_t *d = &s_devices[slot];
        memset(d, 0, sizeof(*d));
        d->in_use = true;
        d->short_addr = r->short_addr;
        memcpy(d->ieee_addr, r->ieee_addr, 8);
        memcpy(d->name, r->name, DEV_NAME_LEN);
        d->name[DEV_NAME_LEN - 1] = '\0';
        memset(d->manufacturer, 0, sizeof(d->manufacturer));
        memcpy(d->manufacturer, r->manufacturer, NVS_MFR_LEN);
        d->manufacturer[NVS_MFR_LEN - 1] = '\0';
        memset(d->model, 0, sizeof(d->model));
        memcpy(d->model, r->model, NVS_MODEL_LEN);
        d->model[NVS_MODEL_LEN - 1] = '\0';
        d->ep_count = r->ep_count > MAX_EP_PER_DEV ? MAX_EP_PER_DEV : r->ep_count;
        d->discovery_done = true;
        d->last_seen_sec = 0; /* Unknown until device communicates */

        for (int e = 0; e < d->ep_count; e++) {
            dev_endpoint_t *ep = &d->endpoints[e];
            ep->id = r->eps[e].id;
            ep->device_id = r->eps[e].device_id;
            ep->has_on_off      = (r->eps[e].flags & 0x01) != 0;
            ep->has_level       = (r->eps[e].flags & 0x02) != 0;
            ep->has_temperature = (r->eps[e].flags & 0x04) != 0;
            ep->has_humidity    = (r->eps[e].flags & 0x08) != 0;
            ep->has_pressure    = (r->eps[e].flags & 0x10) != 0;
            ep->has_illuminance = (r->eps[e].flags & 0x20) != 0;
            ep->has_occupancy   = (r->eps[e].flags & 0x40) != 0;
        }
    }
    device_unlock();

    ESP_LOGI(TAG, "Loaded %d devices from NVS", hdr->count);
    free(buf);
}

/* ── Deferred save (timer callback runs outside Zigbee task) ── */

static void save_timer_cb(void *arg)
{
    (void)arg;
    if (s_save_pending) {
        device_list_save();
        /* Clear after save — if new changes arrived during save,
           they will be picked up on the next timer tick */
        s_save_pending = false;
    }
}

void device_list_save_deferred(void)
{
    s_save_pending = true;
}

void device_list_save_timer_init(void)
{
    const esp_timer_create_args_t args = {
        .callback = save_timer_cb,
        .name = "dev_save",
    };
    ESP_ERROR_CHECK(esp_timer_create(&args, &s_save_timer));
    ESP_ERROR_CHECK(esp_timer_start_periodic(s_save_timer, 2000000)); /* 2s */
}
