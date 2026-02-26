#include "zigbee.h"
#include "ws_server.h"
#include "device_list.h"
#include "device_defs.h"

#include <string.h>
#include <stdarg.h>
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_spiffs.h"
#include "esp_rcp_update.h"
#include "esp_zigbee_secur.h"
#include "esp_zigbee_trace.h"
#include "test/esp_zigbee_test_utils.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_partition.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "ha/esp_zigbee_ha_standard.h"

#if CONFIG_OPENTHREAD_SPINEL_ONLY
#include "esp_radio_spinel.h"
#endif

static const char *TAG = "zigbee";

/* ── Log ring buffer (viewable from web) ──────────────── */

#define LOG_BUF_SIZE  (8 * 1024)
static char    s_log_buf[LOG_BUF_SIZE];
static size_t  s_log_head;
static bool    s_log_wrapped;
static portMUX_TYPE s_log_mux = portMUX_INITIALIZER_UNLOCKED;
static vprintf_like_t s_orig_vprintf;
static volatile bool s_log_in_hook;

static int log_vprintf_hook(const char *fmt, va_list args)
{
    /* Re-entrancy guard: s_orig_vprintf or ws_notify_log may trigger logs */
    if (s_log_in_hook) return 0;
    s_log_in_hook = true;

    /* va_copy BEFORE consuming args — using args after vprintf is UB */
    char tmp[256];
    va_list copy;
    va_copy(copy, args);

    /* Call original first so serial output is preserved */
    int ret = s_orig_vprintf(fmt, args);

    /* Format into a temp buffer */
    int len = vsnprintf(tmp, sizeof(tmp), fmt, copy);
    va_end(copy);
    if (len <= 0) { s_log_in_hook = false; return ret; }
    if (len >= (int)sizeof(tmp)) len = sizeof(tmp) - 1;

    portENTER_CRITICAL_SAFE(&s_log_mux);
    size_t old_head = s_log_head;
    for (int i = 0; i < len; i++) {
        s_log_buf[s_log_head] = tmp[i];
        s_log_head = (s_log_head + 1) % LOG_BUF_SIZE;
    }
    if (old_head + (size_t)len >= LOG_BUF_SIZE) {
        s_log_wrapped = true;
    }
    portEXIT_CRITICAL_SAFE(&s_log_mux);

    ws_notify_log(tmp, len);

    s_log_in_hook = false;
    return ret;
}

size_t zigbee_get_log(char *out, size_t max_len)
{
    if (max_len == 0) return 0;

    portENTER_CRITICAL_SAFE(&s_log_mux);
    size_t total = 0;
    size_t start = s_log_wrapped ? s_log_head : 0;
    size_t end   = s_log_head;

    if (s_log_wrapped) {
        /* Copy from start..end of buffer, then 0..head */
        for (size_t i = start; i < LOG_BUF_SIZE && total < max_len - 1; i++)
            out[total++] = s_log_buf[i];
        for (size_t i = 0; i < end && total < max_len - 1; i++)
            out[total++] = s_log_buf[i];
    } else {
        for (size_t i = 0; i < end && total < max_len - 1; i++)
            out[total++] = s_log_buf[i];
    }
    portEXIT_CRITICAL_SAFE(&s_log_mux);
    out[total] = '\0';
    return total;
}

/* ── State ─────────────────────────────────────────────── */

static volatile bool     s_running;
static volatile bool     s_permit_join;
static volatile uint8_t  s_permit_remain;
static volatile uint16_t s_pan_id;
static volatile uint8_t  s_channel;
static volatile uint16_t s_short_addr;

/* ── RCP error handler ─────────────────────────────────── */

static void rcp_error_handler(void)
{
#if CONFIG_ZIGBEE_GW_AUTO_UPDATE_RCP
    ESP_LOGW(TAG, "RCP error — re-flashing");
    esp_zb_rcp_deinit();
    if (esp_rcp_update() != ESP_OK) {
        esp_rcp_mark_image_verified(false);
    }
#endif
    esp_restart();
}

/* ── RCP version check + auto-update ──────────────────── */

#if CONFIG_OPENTHREAD_SPINEL_ONLY && CONFIG_ZIGBEE_GW_AUTO_UPDATE_RCP
static void rcp_auto_update(const char *running_version)
{
    char stored_version[RCP_VERSION_MAX_SIZE];
    if (esp_rcp_load_version_in_storage(stored_version, sizeof(stored_version)) == ESP_OK) {
        ESP_LOGI(TAG, "Running RCP: %s", running_version);
        ESP_LOGI(TAG, "Storage RCP: %s", stored_version);
        if (strcmp(stored_version, running_version) != 0) {
            ESP_LOGW(TAG, "Version mismatch — updating RCP");
            esp_zb_rcp_deinit();
            if (esp_rcp_update() != ESP_OK) {
                esp_rcp_mark_image_verified(false);
            }
            esp_restart();
        } else {
            ESP_LOGI(TAG, "RCP version matches");
            esp_rcp_mark_image_verified(true);
        }
    } else {
        ESP_LOGW(TAG, "No RCP image in storage, rebooting to try next image");
        esp_rcp_mark_image_verified(false);
        esp_restart();
    }
}
#endif

/* ── ZDO discovery helpers ─────────────────────────────── */

static const char *device_type_name(uint16_t device_id)
{
    switch (device_id) {
        case 0x0000: return "On/Off Switch";
        case 0x0001: return "Level Switch";
        case 0x0002: return "On/Off Output";
        case 0x0100: return "On/Off Light";
        case 0x0101: return "Dimmable Light";
        case 0x0102: return "Color Dimmable Light";
        case 0x0103: return "On/Off Light Switch";
        case 0x0104: return "Dimmer Switch";
        case 0x0105: return "Color Dimmer Switch";
        case 0x0106: return "Light Sensor";
        case 0x0107: return "Occupancy Sensor";
        case 0x0200: return "Shade";
        case 0x0202: return "Window Covering";
        case 0x0301: return "Thermostat";
        case 0x0302: return "Temperature Sensor";
        case 0x0402: return "IAS Zone";
        case 0x0850: return "On/Off Plug-in Unit";
        default:     return "Unknown";
    }
}

static void read_basic_attrs(uint16_t short_addr, uint8_t endpoint);

static void simple_desc_cb(esp_zb_zdp_status_t status, esp_zb_af_simple_desc_1_1_t *desc, void *user_ctx)
{
    if (status != ESP_ZB_ZDP_STATUS_SUCCESS || !desc) return;
    uint16_t addr = (uint16_t)(uintptr_t)user_ctx;

    device_lock();
    int idx = device_find(addr);
    if (idx < 0) { device_unlock(); return; }

    zb_device_t *dev = device_get(idx);
    if (!dev) { device_unlock(); return; }

    /* Check if endpoint already exists (re-discovery after re-announce) */
    dev_endpoint_t *ep = NULL;
    bool is_new_ep = false;
    for (int i = 0; i < dev->ep_count; i++) {
        if (dev->endpoints[i].id == desc->endpoint) {
            ep = &dev->endpoints[i];
            break;
        }
    }
    if (!ep) {
        if (dev->ep_count >= MAX_EP_PER_DEV) { device_unlock(); return; }
        ep = &dev->endpoints[dev->ep_count];
        is_new_ep = true;
    }

    /* Only zero new endpoints — preserve sensor values on re-discovery */
    if (is_new_ep) memset(ep, 0, sizeof(*ep));
    ep->id         = desc->endpoint;
    ep->profile_id = desc->app_profile_id;
    ep->device_id  = desc->app_device_id;

    uint16_t *clusters = (uint16_t *)desc->app_cluster_list;
    for (int i = 0; i < desc->app_input_cluster_count; i++) {
        switch (clusters[i]) {
            case ESP_ZB_ZCL_CLUSTER_ID_ON_OFF:                  ep->has_on_off = true; break;
            case ESP_ZB_ZCL_CLUSTER_ID_LEVEL_CONTROL:           ep->has_level = true; break;
            case ESP_ZB_ZCL_CLUSTER_ID_TEMP_MEASUREMENT:        ep->has_temperature = true; break;
            case ESP_ZB_ZCL_CLUSTER_ID_REL_HUMIDITY_MEASUREMENT: ep->has_humidity = true; break;
            case ESP_ZB_ZCL_CLUSTER_ID_PRESSURE_MEASUREMENT:    ep->has_pressure = true; break;
            case ESP_ZB_ZCL_CLUSTER_ID_ILLUMINANCE_MEASUREMENT: ep->has_illuminance = true; break;
            case ESP_ZB_ZCL_CLUSTER_ID_OCCUPANCY_SENSING:       ep->has_occupancy = true; break;
        }
    }

    if (is_new_ep) dev->ep_count++;
    dev->discovery_done = true;

    /* Read Basic cluster attrs if manufacturer not yet known */
    bool need_basic_read = (dev->manufacturer[0] == '\0');
    uint8_t first_ep = dev->endpoints[0].id;

    ESP_LOGI(TAG, "0x%04X EP%d: device=0x%04X (%s) on_off=%d level=%d temp=%d hum=%d",
             addr, ep->id, ep->device_id, device_type_name(ep->device_id),
             ep->has_on_off, ep->has_level, ep->has_temperature, ep->has_humidity);
    device_unlock();

    if (need_basic_read) {
        read_basic_attrs(addr, first_ep);
    }

    /* Persist updated device list to NVS (deferred — don't block Zigbee task) */
    device_list_save_deferred();
}

static void active_ep_cb(esp_zb_zdp_status_t status, uint8_t ep_count, uint8_t *ep_list, void *user_ctx)
{
    if (status != ESP_ZB_ZDP_STATUS_SUCCESS) return;
    uint16_t addr = (uint16_t)(uintptr_t)user_ctx;
    ESP_LOGI(TAG, "0x%04X: %d endpoints", addr, ep_count);

    for (int i = 0; i < ep_count; i++) {
        esp_zb_zdo_simple_desc_req_param_t req = {
            .addr_of_interest = addr,
            .endpoint = ep_list[i],
        };
        esp_zb_zdo_simple_desc_req(&req, simple_desc_cb, (void *)(uintptr_t)addr);
    }
}

static void discover_device(uint16_t short_addr)
{
    esp_zb_zdo_active_ep_req_param_t req = {
        .addr_of_interest = short_addr,
    };
    esp_zb_zdo_active_ep_req(&req, active_ep_cb, (void *)(uintptr_t)short_addr);
}

/* ── Auto-bind queue ──────────────────────────────────── */

#define BIND_QUEUE_SIZE 16

typedef struct {
    uint16_t short_addr;
    uint8_t  ieee_addr[8];
    uint8_t  src_ep;
    uint16_t cluster_id;
} bind_entry_t;

static bind_entry_t s_bind_queue[BIND_QUEUE_SIZE];
static int  s_bind_head, s_bind_tail;
static bool s_bind_busy;

static void process_next_bind(void);

static void bind_cb(esp_zb_zdp_status_t status, void *user_ctx)
{
    bind_entry_t *e = (bind_entry_t *)user_ctx;
    if (status == ESP_ZB_ZDP_STATUS_SUCCESS) {
        ESP_LOGI(TAG, "Bind OK: 0x%04X EP%d cluster 0x%04X", e->short_addr, e->src_ep, e->cluster_id);
    } else {
        ESP_LOGW(TAG, "Bind FAIL (0x%02X): 0x%04X EP%d cluster 0x%04X",
                 status, e->short_addr, e->src_ep, e->cluster_id);
    }
    s_bind_head = (s_bind_head + 1) % BIND_QUEUE_SIZE;
    s_bind_busy = false;
    process_next_bind();
}

static void process_next_bind(void)
{
    if (s_bind_busy || s_bind_head == s_bind_tail) return;

    bind_entry_t *e = &s_bind_queue[s_bind_head];
    s_bind_busy = true;

    esp_zb_zdo_bind_req_param_t req = {0};
    memcpy(req.src_address, e->ieee_addr, 8);
    req.src_endp = e->src_ep;
    req.cluster_id = e->cluster_id;
    req.dst_addr_mode = ESP_ZB_ZDO_BIND_DST_ADDR_MODE_64_BIT_EXTENDED;
    esp_zb_get_long_address(req.dst_address_u.addr_long);
    req.dst_endp = GW_ENDPOINT;
    req.req_dst_addr = e->short_addr;

    ESP_LOGI(TAG, "Binding 0x%04X EP%d cluster 0x%04X -> coordinator",
             e->short_addr, e->src_ep, e->cluster_id);
    esp_zb_zdo_device_bind_req(&req, bind_cb, (void *)e);
}

static void zigbee_start_autobind(uint16_t short_addr, const uint8_t *ieee_addr,
                                   const device_def_t *def)
{
    for (int b = 0; b < def->bind_count; b++) {
        const dev_def_bind_t *bd = &def->binds[b];
        for (int c = 0; c < bd->cluster_count; c++) {
            int next = (s_bind_tail + 1) % BIND_QUEUE_SIZE;
            if (next == s_bind_head) {
                ESP_LOGW(TAG, "Bind queue full, dropping");
                goto done;
            }
            bind_entry_t *e = &s_bind_queue[s_bind_tail];
            e->short_addr = short_addr;
            memcpy(e->ieee_addr, ieee_addr, 8);
            e->src_ep = bd->endpoint;
            e->cluster_id = bd->clusters[c];
            s_bind_tail = next;
        }
    }
done:
    process_next_bind();
}

/* ── Read Basic cluster attrs (manufacturer + model) ──── */

static void read_basic_attrs(uint16_t short_addr, uint8_t endpoint)
{
    static uint16_t attrs[] = {
        ESP_ZB_ZCL_ATTR_BASIC_MANUFACTURER_NAME_ID,  /* 0x0004 */
        ESP_ZB_ZCL_ATTR_BASIC_MODEL_IDENTIFIER_ID,   /* 0x0005 */
    };
    esp_zb_zcl_read_attr_cmd_t cmd = {
        .zcl_basic_cmd = {
            .dst_addr_u.addr_short = short_addr,
            .dst_endpoint = endpoint,
            .src_endpoint = GW_ENDPOINT,
        },
        .address_mode = ESP_ZB_APS_ADDR_MODE_16_ENDP_PRESENT,
        .clusterID    = ESP_ZB_ZCL_CLUSTER_ID_BASIC,
        .attr_number  = 2,
        .attr_field   = attrs,
    };
    ESP_LOGI(TAG, "Reading Basic attrs from 0x%04X EP%d", short_addr, endpoint);
    esp_zb_zcl_read_attr_cmd_req(&cmd);
}

/* ── BDB commissioning helper ─────────────────────────── */

static void bdb_start_top_level_commissioning_cb(uint8_t mode_mask)
{
    ESP_ERROR_CHECK_WITHOUT_ABORT(esp_zb_bdb_start_top_level_commissioning(mode_mask));
}

/* ── Signal handler (network events) ──────────────────── */

void esp_zb_app_signal_handler(esp_zb_app_signal_t *signal_struct)
{
    uint32_t *p_sg_p     = signal_struct->p_app_signal;
    esp_err_t err_status = signal_struct->esp_err_status;
    esp_zb_app_signal_type_t sig_type = *p_sg_p;

    switch (sig_type) {
    case ESP_ZB_ZDO_SIGNAL_SKIP_STARTUP:
        ESP_LOGI(TAG, "Zigbee stack initialized");
        esp_zb_bdb_start_top_level_commissioning(ESP_ZB_BDB_MODE_INITIALIZATION);
        break;

    case ESP_ZB_BDB_SIGNAL_DEVICE_FIRST_START:
    case ESP_ZB_BDB_SIGNAL_DEVICE_REBOOT:
        if (err_status == ESP_OK) {
            s_running = true;
            s_pan_id     = esp_zb_get_pan_id();
            s_channel    = esp_zb_get_current_channel();
            s_short_addr = esp_zb_get_short_address();
            ws_notify_status();

            if (esp_zb_bdb_is_factory_new()) {
                ESP_LOGI(TAG, "Factory new — forming network");
                esp_zb_bdb_start_top_level_commissioning(ESP_ZB_BDB_MODE_NETWORK_FORMATION);
            } else {
                ESP_LOGI(TAG, "Network restored (PAN 0x%04X CH %d)",
                         s_pan_id, s_channel);
                esp_zb_bdb_open_network(180);
            }
        } else {
            ESP_LOGW(TAG, "Init failed: %s, retrying...", esp_err_to_name(err_status));
            esp_zb_scheduler_alarm((esp_zb_callback_t)bdb_start_top_level_commissioning_cb,
                                   ESP_ZB_BDB_MODE_INITIALIZATION, 1000);
        }
        break;

    case ESP_ZB_BDB_SIGNAL_FORMATION:
        if (err_status == ESP_OK) {
            s_pan_id  = esp_zb_get_pan_id();
            s_channel = esp_zb_get_current_channel();
            ESP_LOGI(TAG, "Network formed (PAN 0x%04X CH %d)", s_pan_id, s_channel);
            ws_notify_status();
            esp_zb_bdb_start_top_level_commissioning(ESP_ZB_BDB_MODE_NETWORK_STEERING);
        } else {
            ESP_LOGW(TAG, "Formation failed, retrying...");
            esp_zb_scheduler_alarm((esp_zb_callback_t)bdb_start_top_level_commissioning_cb,
                                   ESP_ZB_BDB_MODE_NETWORK_FORMATION, 1000);
        }
        break;

    case ESP_ZB_BDB_SIGNAL_STEERING:
        if (err_status == ESP_OK) {
            ESP_LOGI(TAG, "Network steering started");
        }
        break;

    case ESP_ZB_ZDO_SIGNAL_DEVICE_ANNCE: {
        esp_zb_zdo_signal_device_annce_params_t *annce =
            (esp_zb_zdo_signal_device_annce_params_t *)esp_zb_app_signal_get_params(p_sg_p);
        if (!annce) break;
        ESP_LOGI(TAG, "Device announced: 0x%04X IEEE:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X",
                 annce->device_short_addr,
                 annce->ieee_addr[7], annce->ieee_addr[6],
                 annce->ieee_addr[5], annce->ieee_addr[4],
                 annce->ieee_addr[3], annce->ieee_addr[2],
                 annce->ieee_addr[1], annce->ieee_addr[0]);
        device_add(annce->device_short_addr, annce->ieee_addr);
        discover_device(annce->device_short_addr);
        ws_notify_devices();
        break;
    }

    case ESP_ZB_NWK_SIGNAL_PERMIT_JOIN_STATUS:
        if (err_status == ESP_OK) {
            void *pj_params = esp_zb_app_signal_get_params(p_sg_p);
            if (!pj_params) break;
            uint8_t dur = *(uint8_t *)pj_params;
            s_permit_join = (dur > 0);
            s_permit_remain = dur;
            ws_notify_permit_join(dur > 0, dur);
            if (dur > 0) {
                ESP_LOGI(TAG, "Network open for %ds", dur);
            } else {
                ESP_LOGI(TAG, "Network closed");
            }
        }
        break;

    case ESP_ZB_ZDO_SIGNAL_LEAVE_INDICATION: {
        esp_zb_zdo_signal_leave_indication_params_t *leave =
            (esp_zb_zdo_signal_leave_indication_params_t *)esp_zb_app_signal_get_params(p_sg_p);
        if (!leave) break;
        uint16_t left_addr = 0;
        device_lock();
        int idx = device_find_by_ieee(leave->device_addr);
        if (idx >= 0) {
            left_addr = device_get(idx)->short_addr;
            ESP_LOGI(TAG, "Device left: 0x%04X", left_addr);
            device_remove(idx);
        } else {
            ESP_LOGI(TAG, "Unknown device left (IEEE:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X)",
                     leave->device_addr[7], leave->device_addr[6],
                     leave->device_addr[5], leave->device_addr[4],
                     leave->device_addr[3], leave->device_addr[2],
                     leave->device_addr[1], leave->device_addr[0]);
        }
        device_unlock();
        if (idx >= 0) {
            device_list_save_deferred();
            ws_notify_device_remove(left_addr);
        }
        break;
    }

    case ESP_ZB_NWK_SIGNAL_DEVICE_ASSOCIATED: {
        esp_zb_nwk_signal_device_associated_params_t *assoc =
            (esp_zb_nwk_signal_device_associated_params_t *)esp_zb_app_signal_get_params(p_sg_p);
        if (!assoc) break;
        ESP_LOGW(TAG, "Device ASSOCIATED (MAC level): IEEE:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X",
                 assoc->device_addr[7], assoc->device_addr[6],
                 assoc->device_addr[5], assoc->device_addr[4],
                 assoc->device_addr[3], assoc->device_addr[2],
                 assoc->device_addr[1], assoc->device_addr[0]);
        break;
    }

    case ESP_ZB_ZDO_SIGNAL_DEVICE_UPDATE: {
        esp_zb_zdo_signal_device_update_params_t *upd =
            (esp_zb_zdo_signal_device_update_params_t *)esp_zb_app_signal_get_params(p_sg_p);
        if (!upd) break;
        const char *status_str = "unknown";
        switch (upd->status) {
            case 0: status_str = "secure_rejoin"; break;
            case 1: status_str = "unsecure_join"; break;
            case 2: status_str = "left"; break;
            case 3: status_str = "tc_rejoin"; break;
        }
        const char *tc_str = "unknown";
        switch (upd->tc_action) {
            case 0: tc_str = "authorize"; break;
            case 1: tc_str = "DENY"; break;
            case 2: tc_str = "ignore"; break;
        }
        ESP_LOGW(TAG, "Device UPDATE: 0x%04X status=%s tc_action=%s IEEE:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X",
                 upd->short_addr, status_str, tc_str,
                 upd->long_addr[7], upd->long_addr[6],
                 upd->long_addr[5], upd->long_addr[4],
                 upd->long_addr[3], upd->long_addr[2],
                 upd->long_addr[1], upd->long_addr[0]);
        break;
    }

    case ESP_ZB_ZDO_SIGNAL_DEVICE_AUTHORIZED: {
        esp_zb_zdo_signal_device_authorized_params_t *auth =
            (esp_zb_zdo_signal_device_authorized_params_t *)esp_zb_app_signal_get_params(p_sg_p);
        if (!auth) break;
        ESP_LOGW(TAG, "Device AUTHORIZED: 0x%04X type=%d status=%d IEEE:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X",
                 auth->short_addr, auth->authorization_type, auth->authorization_status,
                 auth->long_addr[7], auth->long_addr[6],
                 auth->long_addr[5], auth->long_addr[4],
                 auth->long_addr[3], auth->long_addr[2],
                 auth->long_addr[1], auth->long_addr[0]);
        break;
    }

    case ESP_ZB_NLME_STATUS_INDICATION: {
        ESP_LOGI(TAG, "NLME status indication, status: %s", esp_err_to_name(err_status));
        break;
    }

    case ESP_ZB_ZDO_SIGNAL_PRODUCTION_CONFIG_READY:
        ESP_LOGI(TAG, "Production config ready, status: %s", esp_err_to_name(err_status));
        break;

    default:
        /* Log ALL signals at INFO level for debugging */
        ESP_LOGI(TAG, "Signal: %s (0x%x), status: %s",
                 esp_zb_zdo_signal_to_string(sig_type), sig_type,
                 esp_err_to_name(err_status));
        break;
    }
}

/* ── ZCL action handler ───────────────────────────────── */

static esp_err_t zb_action_handler(esp_zb_core_action_callback_id_t callback_id,
                                    const void *message)
{
    if (callback_id == ESP_ZB_CORE_REPORT_ATTR_CB_ID) {
        esp_zb_zcl_report_attr_message_t *msg = (esp_zb_zcl_report_attr_message_t *)message;
        if (!msg || msg->status != ESP_ZB_ZCL_STATUS_SUCCESS) return ESP_OK;

        uint16_t addr = msg->src_address.u.short_addr;
        uint8_t  ep   = msg->src_endpoint;

        bool save_needed = false;
        device_lock();
        int idx = device_find(addr);
        if (idx >= 0) {
            zb_device_t *dev = device_get(idx);
            dev->last_seen_sec = esp_timer_get_time() / 1000000;

            dev_endpoint_t *dep = NULL;
            for (int i = 0; i < dev->ep_count; i++) {
                if (dev->endpoints[i].id == ep) { dep = &dev->endpoints[i]; break; }
            }
            /* Auto-create endpoint from reports if simple_desc never arrived */
            if (!dep && dev->ep_count < MAX_EP_PER_DEV) {
                dep = &dev->endpoints[dev->ep_count];
                memset(dep, 0, sizeof(*dep));
                dep->id = ep;
                dep->profile_id = ESP_ZB_AF_HA_PROFILE_ID;
                dev->ep_count++;
                dev->discovery_done = true;
                ESP_LOGI(TAG, "0x%04X EP%d: auto-created from report", addr, ep);
                save_needed = true;
                /* Also read Basic attrs if not yet known */
                if (dev->manufacturer[0] == '\0') {
                    read_basic_attrs(addr, ep);
                }
            }
            if (dep && msg->attribute.data.value) {
                uint16_t cluster = msg->cluster;
                uint16_t attr    = msg->attribute.id;

                if (cluster == ESP_ZB_ZCL_CLUSTER_ID_ON_OFF &&
                    attr == ESP_ZB_ZCL_ATTR_ON_OFF_ON_OFF_ID) {
                    dep->has_on_off = true;
                    dep->on_off_state = *(bool *)msg->attribute.data.value;
                    ESP_LOGI(TAG, "0x%04X EP%d: on_off=%s", addr, ep, dep->on_off_state ? "ON" : "OFF");
                }
                else if (cluster == ESP_ZB_ZCL_CLUSTER_ID_TEMP_MEASUREMENT &&
                         attr == ESP_ZB_ZCL_ATTR_TEMP_MEASUREMENT_VALUE_ID) {
                    dep->has_temperature = true;
                    dep->temperature = *(int16_t *)msg->attribute.data.value;
                    ESP_LOGI(TAG, "0x%04X EP%d: temperature=%.1f°C", addr, ep, dep->temperature / 100.0);
                }
                else if (cluster == ESP_ZB_ZCL_CLUSTER_ID_REL_HUMIDITY_MEASUREMENT &&
                         attr == ESP_ZB_ZCL_ATTR_REL_HUMIDITY_MEASUREMENT_VALUE_ID) {
                    dep->has_humidity = true;
                    dep->humidity = *(uint16_t *)msg->attribute.data.value;
                    ESP_LOGI(TAG, "0x%04X EP%d: humidity=%.1f%%", addr, ep, dep->humidity / 100.0);
                }
                else if (cluster == ESP_ZB_ZCL_CLUSTER_ID_LEVEL_CONTROL &&
                         attr == ESP_ZB_ZCL_ATTR_LEVEL_CONTROL_CURRENT_LEVEL_ID) {
                    dep->has_level = true;
                    dep->level = *(uint8_t *)msg->attribute.data.value;
                    ESP_LOGI(TAG, "0x%04X EP%d: level=%d (%d%%)", addr, ep, dep->level, dep->level * 100 / 255);
                }
                else if (cluster == ESP_ZB_ZCL_CLUSTER_ID_ILLUMINANCE_MEASUREMENT &&
                         attr == ESP_ZB_ZCL_ATTR_ILLUMINANCE_MEASUREMENT_MEASURED_VALUE_ID) {
                    dep->has_illuminance = true;
                    dep->illuminance = *(uint16_t *)msg->attribute.data.value;
                    ESP_LOGI(TAG, "0x%04X EP%d: illuminance=%d lux", addr, ep, dep->illuminance);
                }
                else if (cluster == ESP_ZB_ZCL_CLUSTER_ID_OCCUPANCY_SENSING &&
                         attr == ESP_ZB_ZCL_ATTR_OCCUPANCY_SENSING_OCCUPANCY_ID) {
                    dep->has_occupancy = true;
                    dep->occupancy = *(uint8_t *)msg->attribute.data.value;
                    ESP_LOGI(TAG, "0x%04X EP%d: occupancy=%s", addr, ep, dep->occupancy ? "occupied" : "clear");
                }
                else if (cluster == ESP_ZB_ZCL_CLUSTER_ID_PRESSURE_MEASUREMENT &&
                         attr == ESP_ZB_ZCL_ATTR_PRESSURE_MEASUREMENT_VALUE_ID) {
                    dep->has_pressure = true;
                    dep->pressure = *(int16_t *)msg->attribute.data.value;
                    ESP_LOGI(TAG, "0x%04X EP%d: pressure=%d hPa", addr, ep, dep->pressure);
                }
                else {
                    ESP_LOGI(TAG, "0x%04X EP%d: cluster=0x%04X attr=0x%04X (unhandled)", addr, ep, cluster, attr);
                }
            }
        }
        device_unlock();
        if (save_needed) device_list_save_deferred();
        ws_notify_device_update(addr);
    }
    else if (callback_id == ESP_ZB_CORE_CMD_READ_ATTR_RESP_CB_ID) {
        esp_zb_zcl_cmd_read_attr_resp_message_t *msg =
            (esp_zb_zcl_cmd_read_attr_resp_message_t *)message;
        if (!msg || msg->info.status != ESP_ZB_ZCL_STATUS_SUCCESS) return ESP_OK;
        if (msg->info.cluster != ESP_ZB_ZCL_CLUSTER_ID_BASIC) return ESP_OK;

        uint16_t addr = msg->info.src_address.u.short_addr;
        char manufacturer[32] = {0};
        char model[32] = {0};

        /* Iterate attribute response list */
        esp_zb_zcl_read_attr_resp_variable_t *var = msg->variables;
        while (var) {
            if (var->status == ESP_ZB_ZCL_STATUS_SUCCESS && var->attribute.data.value) {
                /* ZCL string: first byte = length, then chars (no null terminator) */
                uint8_t *raw = (uint8_t *)var->attribute.data.value;
                uint8_t slen = raw[0];
                if (slen == 0xFF) slen = 0;  /* 0xFF = invalid ZCL string */
                if (slen > 30) slen = 30;  /* cap to fit our buffer */
                /* Validate against reported data size (size includes length byte) */
                if (var->attribute.data.size > 0 && slen > var->attribute.data.size - 1) {
                    slen = var->attribute.data.size - 1;
                }

                if (var->attribute.id == ESP_ZB_ZCL_ATTR_BASIC_MANUFACTURER_NAME_ID) {
                    memcpy(manufacturer, raw + 1, slen);
                    manufacturer[slen] = '\0';
                } else if (var->attribute.id == ESP_ZB_ZCL_ATTR_BASIC_MODEL_IDENTIFIER_ID) {
                    memcpy(model, raw + 1, slen);
                    model[slen] = '\0';
                }
            }
            var = var->next;
        }

        if (manufacturer[0] || model[0]) {
            ESP_LOGI(TAG, "0x%04X Basic: manufacturer=\"%s\" model=\"%s\"",
                     addr, manufacturer, model);

            bool do_bind = false;
            uint8_t ieee[8];
            device_def_t def_copy;

            device_lock();
            int idx = device_find(addr);
            if (idx >= 0) {
                zb_device_t *dev = device_get(idx);
                if (manufacturer[0]) strncpy(dev->manufacturer, manufacturer, sizeof(dev->manufacturer) - 1);
                if (model[0]) strncpy(dev->model, model, sizeof(dev->model) - 1);
                memcpy(ieee, dev->ieee_addr, 8);

                /* Copy def data — pointer may become stale after unlock */
                const device_def_t *def = device_defs_find(dev->manufacturer, dev->model);
                if (def && def->bind_count > 0) {
                    memcpy(&def_copy, def, sizeof(def_copy));
                    do_bind = true;
                }
            }
            device_unlock();
            ws_notify_device_update(addr);

            if (do_bind) {
                ESP_LOGI(TAG, "0x%04X matched definition, starting auto-bind", addr);
                zigbee_start_autobind(addr, ieee, &def_copy);
            }
        }
    }
    return ESP_OK;
}

/* ── Zigbee task ──────────────────────────────────────── */

static void zigbee_task(void *pvParams)
{
#if CONFIG_OPENTHREAD_SPINEL_ONLY
    esp_radio_spinel_register_rcp_failure_handler(rcp_error_handler, ESP_RADIO_SPINEL_ZIGBEE);
#endif

    /* Init as coordinator */
    esp_zb_cfg_t zb_cfg = ESP_ZB_ZC_CONFIG();
    esp_zb_init(&zb_cfg);

    /* ── Legacy device support (Xiaomi, IKEA old gen, etc.) ── */
    /* Allow devices that don't do TC Link Key exchange to stay in the network */
    esp_zb_secur_link_key_exchange_required_set(false);
    /* Don't require install codes — accept any device */
    esp_zb_secur_ic_only_enable(false);
    /* Set minimum join LQI to 0 — don't reject weak-signal devices */
    esp_zb_secur_network_min_join_lqi_set(0);
    /* Allow TC rejoin — devices can rejoin through Trust Center */
    esp_zb_secur_tcpol_set_allow_tc_rejoins(1);
    /* Allow unsecure TC rejoin — devices without valid link key can rejoin */
    esp_zb_secur_set_unsecure_tc_rejoin_enabled(true);
    ESP_LOGI(TAG, "Security: legacy support ENABLED (no TCLK, TC rejoin allowed)");

#if CONFIG_OPENTHREAD_SPINEL_ONLY
    /* Check RCP version, auto-update if needed */
    char rcp_ver[RCP_VERSION_MAX_SIZE];
    if (esp_radio_spinel_rcp_version_get(rcp_ver, ESP_RADIO_SPINEL_ZIGBEE) == ESP_OK) {
        ESP_LOGI(TAG, "Running RCP Version: %s", rcp_ver);
#if CONFIG_ZIGBEE_GW_AUTO_UPDATE_RCP
        rcp_auto_update(rcp_ver);
#endif
    }
#endif

    /* Channel mask — check NVS override first */
    uint32_t channel_mask = GW_CHANNEL_MASK;
    {
        nvs_handle_t nvs;
        if (nvs_open("zigbee_cfg", NVS_READONLY, &nvs) == ESP_OK) {
            uint8_t ch = 0;
            if (nvs_get_u8(nvs, "channel", &ch) == ESP_OK && ch >= 11 && ch <= 26) {
                channel_mask = (1UL << ch);
                ESP_LOGI(TAG, "Channel from NVS: %d", ch);
            }
            nvs_close(nvs);
        }
    }
    esp_zb_set_primary_network_channel_set(channel_mask);
    ESP_LOGI(TAG, "Channel mask: 0x%08lx", (unsigned long)channel_mask);

    /* Create coordinator endpoint */
    esp_zb_ep_list_t *ep_list = esp_zb_ep_list_create();
    esp_zb_cluster_list_t *cluster_list = esp_zb_zcl_cluster_list_create();

    esp_zb_attribute_list_t *basic_cl = esp_zb_basic_cluster_create(NULL);
    esp_zb_basic_cluster_add_attr(basic_cl, ESP_ZB_ZCL_ATTR_BASIC_MANUFACTURER_NAME_ID, ESP_MANUFACTURER_NAME);
    esp_zb_basic_cluster_add_attr(basic_cl, ESP_ZB_ZCL_ATTR_BASIC_MODEL_IDENTIFIER_ID, ESP_MODEL_IDENTIFIER);
    esp_zb_cluster_list_add_basic_cluster(cluster_list, basic_cl, ESP_ZB_ZCL_CLUSTER_SERVER_ROLE);
    esp_zb_cluster_list_add_identify_cluster(cluster_list, esp_zb_identify_cluster_create(NULL), ESP_ZB_ZCL_CLUSTER_SERVER_ROLE);

    esp_zb_endpoint_config_t ep_cfg = {
        .endpoint       = GW_ENDPOINT,
        .app_profile_id = ESP_ZB_AF_HA_PROFILE_ID,
        .app_device_id  = ESP_ZB_HA_REMOTE_CONTROL_DEVICE_ID,
        .app_device_version = 0,
    };
    esp_zb_ep_list_add_gateway_ep(ep_list, cluster_list, ep_cfg);
    esp_zb_device_register(ep_list);

    esp_zb_core_action_handler_register(zb_action_handler);

    /* ZBOSS trace — WARNING level only (DEBUG floods 8KB log buffer) */
    esp_zb_set_trace_level_mask(ESP_ZB_TRACE_LEVEL_WARN,
        ESP_ZB_TRACE_SUBSYSTEM_MAC |
        ESP_ZB_TRACE_SUBSYSTEM_NWK |
        ESP_ZB_TRACE_SUBSYSTEM_ZDO |
        ESP_ZB_TRACE_SUBSYSTEM_SECUR);

    ESP_LOGI(TAG, "Starting Zigbee coordinator...");
    ESP_ERROR_CHECK(esp_zb_start(false));

    /* Blocks forever */
    esp_zb_stack_main_loop();

    esp_rcp_update_deinit();
    vTaskDelete(NULL);
}

/* ── Public API ────────────────────────────────────────── */

esp_err_t zigbee_platform_init(void)
{
    /* Hook into ESP log system to capture logs for web viewer */
    memset(s_log_buf, 0, sizeof(s_log_buf));
    s_log_head = 0;
    s_orig_vprintf = esp_log_set_vprintf(log_vprintf_hook);

    esp_zb_platform_config_t config = {
        .radio_config = ESP_ZB_DEFAULT_RADIO_CONFIG(),
        .host_config  = ESP_ZB_DEFAULT_HOST_CONFIG(),
    };
    return esp_zb_platform_config(&config);
}

esp_err_t zigbee_rcp_update_init(void)
{
#if CONFIG_ZIGBEE_GW_AUTO_UPDATE_RCP
    esp_vfs_spiffs_conf_t spiffs_conf = {
        .base_path = "/rcp_fw",
        .partition_label = "rcp_fw",
        .max_files = 10,
        .format_if_mount_failed = false,
    };
    esp_err_t err = esp_vfs_spiffs_register(&spiffs_conf);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "SPIFFS mount failed (0x%x) — RCP auto-update disabled", err);
        return ESP_OK; /* Non-fatal */
    }

    esp_rcp_update_config_t rcp_cfg = ESP_ZB_RCP_UPDATE_CONFIG();
    return esp_rcp_update_init(&rcp_cfg);
#else
    return ESP_OK;
#endif
}

esp_err_t zigbee_start(void)
{
    BaseType_t ret = xTaskCreate(zigbee_task, "zigbee", 8192, NULL, 5, NULL);
    return ret == pdPASS ? ESP_OK : ESP_FAIL;
}

void zigbee_get_status(zigbee_status_t *out)
{
    out->running              = s_running;
    out->pan_id               = s_pan_id;
    out->channel              = s_channel;
    out->short_addr           = s_short_addr;
    out->permit_join          = s_permit_join;
    out->permit_join_remaining = s_permit_remain;

    device_lock();
    out->device_count = device_count();
    device_unlock();
}

void zigbee_permit_join(uint8_t duration_sec)
{
    esp_zb_lock_acquire(portMAX_DELAY);
    esp_zb_bdb_open_network(duration_sec);
    esp_zb_lock_release();
    ESP_LOGI(TAG, "Permit join: %ds", duration_sec);
}

void zigbee_send_on_off(uint16_t addr, uint8_t endpoint, uint8_t cmd)
{
    esp_zb_zcl_on_off_cmd_t cmd_req = {
        .zcl_basic_cmd = {
            .dst_addr_u.addr_short = addr,
            .dst_endpoint = endpoint,
            .src_endpoint = GW_ENDPOINT,
        },
        .address_mode  = ESP_ZB_APS_ADDR_MODE_16_ENDP_PRESENT,
        .on_off_cmd_id = cmd,
    };

    esp_zb_lock_acquire(portMAX_DELAY);
    esp_zb_zcl_on_off_cmd_req(&cmd_req);
    esp_zb_lock_release();

    ESP_LOGI(TAG, "On/Off cmd=%d -> 0x%04X EP%d", cmd, addr, endpoint);
}

void zigbee_read_attribute(uint16_t addr, uint8_t endpoint,
                           uint16_t cluster, uint16_t attr_id)
{
    uint16_t attrs[] = { attr_id };
    esp_zb_zcl_read_attr_cmd_t cmd = {
        .zcl_basic_cmd = {
            .dst_addr_u.addr_short = addr,
            .dst_endpoint = endpoint,
            .src_endpoint = GW_ENDPOINT,
        },
        .address_mode = ESP_ZB_APS_ADDR_MODE_16_ENDP_PRESENT,
        .clusterID    = cluster,
        .attr_number  = 1,
        .attr_field   = attrs,
    };

    esp_zb_lock_acquire(portMAX_DELAY);
    esp_zb_zcl_read_attr_cmd_req(&cmd);
    esp_zb_lock_release();
}

static void erase_zigbee_partitions(void)
{
    const char *labels[] = {"zb_storage", "zb_fct"};
    for (int i = 0; i < 2; i++) {
        const esp_partition_t *part = esp_partition_find_first(
            ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_ANY, labels[i]);
        if (part) {
            ESP_LOGW(TAG, "Erasing partition '%s' (%lx bytes)", labels[i], (unsigned long)part->size);
            esp_err_t erase_err = esp_partition_erase_range(part, 0, part->size);
            if (erase_err != ESP_OK) {
                ESP_LOGE(TAG, "Erase '%s' failed: %s", labels[i], esp_err_to_name(erase_err));
            }
        }
    }
}

void zigbee_set_channel(uint8_t channel)
{
    nvs_handle_t nvs;
    if (nvs_open("zigbee_cfg", NVS_READWRITE, &nvs) == ESP_OK) {
        if (channel >= 11 && channel <= 26) {
            nvs_set_u8(nvs, "channel", channel);
        } else {
            nvs_erase_key(nvs, "channel");
        }
        nvs_commit(nvs);
        nvs_close(nvs);
    }

    ESP_LOGW(TAG, "Channel set to %d — erasing Zigbee storage + restart", channel);

    /* Erase Zigbee partitions directly — esp_zb_factory_reset() is unreliable
       when called from outside the Zigbee task */
    erase_zigbee_partitions();

    vTaskDelay(pdMS_TO_TICKS(200));
    esp_restart();
}

void zigbee_factory_reset(void)
{
    ESP_LOGW(TAG, "Factory reset — erasing Zigbee storage + NVS channel + restart");
    erase_zigbee_partitions();

    /* Also clear NVS channel override so default (CH 25) is used */
    nvs_handle_t nvs;
    if (nvs_open("zigbee_cfg", NVS_READWRITE, &nvs) == ESP_OK) {
        nvs_erase_key(nvs, "channel");
        nvs_commit(nvs);
        nvs_close(nvs);
    }

    vTaskDelay(pdMS_TO_TICKS(200));
    esp_restart();
}
