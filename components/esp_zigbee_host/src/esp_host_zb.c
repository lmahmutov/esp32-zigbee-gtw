/*
 * SPDX-FileCopyrightText: 2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>

#include "nvs_flash.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/timers.h"
#include "esp_log.h"
#include "esp_check.h"
#include "esp_system.h"
#include "esp_random.h"

#include "esp_host_main.h"
#include "esp_host_zb.h"

#include "zb_config_platform.h"
#include "esp_zigbee_core.h"
#include "esp_zigbee_zcl_command.h"

static const char *TAG = "ESP_HOST_ZB";

typedef struct {
    esp_zb_ieee_addr_t  extendedPanId;                      /*!< The network's extended PAN identifier */
    uint16_t            panId;                              /*!< The network's PAN identifier */
    uint8_t             radioChannel;                       /*!< A radio channel */
} esp_host_zb_network_t;

/**
 * @brief Type to represent the sync event between the host and BUS.
 *
 */
typedef struct {
    uint16_t        id;                                     /*!< The frame ID */
    uint16_t        size;                                   /*!< Data size on the event */
    void            *data;                                  /*!< Data on the event */
} esp_host_zb_ctx_t;

static esp_host_zb_network_t        s_host_zb_network;
static QueueHandle_t                output_queue;           /*!< The queue handler for wait response */
static QueueHandle_t                notify_queue;           /*!< The queue handler for wait notification */
static SemaphoreHandle_t            lock_semaphore;

/* Action handler callback — dispatches ZCL attribute reports and read responses */
static esp_zb_core_action_handler_t s_action_handler = NULL;

static esp_err_t esp_host_zb_form_network_fn(const uint8_t *input, uint16_t inlen)
{
    typedef struct {
        esp_zb_ieee_addr_t  extendedPanId;                  /*!< The network's extended PAN identifier */
        uint16_t            panId;                          /*!< The network's PAN identifier */
        uint8_t             radioChannel;                   /*!< A radio channel */
    } ESP_ZNSP_ZB_PACKED_STRUCT esp_zb_form_network_t;

    esp_zb_form_network_t *form_network = (esp_zb_form_network_t *)input;
    esp_zb_app_signal_msg_t signal_msg = {
        .signal = ESP_ZB_BDB_SIGNAL_FORMATION,
        .msg = NULL,
    };

    esp_zb_app_signal_t app_signal = {
        .p_app_signal = (uint32_t *)&signal_msg,
        .esp_err_status = ESP_OK,
    };

    memcpy(s_host_zb_network.extendedPanId, form_network->extendedPanId, sizeof(esp_zb_ieee_addr_t));
    s_host_zb_network.panId = form_network->panId;
    s_host_zb_network.radioChannel = form_network->radioChannel;

    esp_zb_app_signal_handler(&app_signal);

    return ESP_OK;
}

static esp_err_t esp_host_zb_joining_network_fn(const uint8_t *input, uint16_t inlen)
{
    esp_zb_app_signal_msg_t signal_msg = {
        .signal = ESP_ZB_ZDO_SIGNAL_DEVICE_ANNCE,
        .msg = (const char *)input,
    };

    esp_zb_app_signal_t app_signal = {
        .p_app_signal = (uint32_t *)&signal_msg,
        .esp_err_status = ESP_OK,
    };

    esp_zb_app_signal_handler(&app_signal);

    return ESP_OK;
}

static esp_err_t esp_host_zb_permit_joining_fn(const uint8_t *input, uint16_t inlen)
{
    esp_zb_app_signal_msg_t signal_msg = {
        .signal = ESP_ZB_NWK_SIGNAL_PERMIT_JOIN_STATUS,
        .msg = (const char *)input,
    };

    esp_zb_app_signal_t app_signal = {
        .p_app_signal = (uint32_t *)&signal_msg,
        .esp_err_status = ESP_OK,
    };

    esp_zb_app_signal_handler(&app_signal);

    return ESP_OK;
}

static esp_err_t esp_host_zb_leave_network_fn(const uint8_t *input, uint16_t inlen)
{
    esp_zb_app_signal_msg_t signal_msg = {
        .signal = ESP_ZB_ZDO_SIGNAL_LEAVE,
        .msg = (const char *)input,
    };

    esp_zb_app_signal_t app_signal = {
        .p_app_signal = (uint32_t *)&signal_msg,
        .esp_err_status = ESP_OK,
    };

    esp_zb_app_signal_handler(&app_signal);

    return ESP_OK;
}

static esp_err_t esp_host_zb_set_bind_fn(const uint8_t *input, uint16_t inlen)
{
    typedef struct {
        esp_zb_zdp_status_t    zdo_status;
        esp_zb_user_cb_t       bind_usr;                   /*!< A ZDO bind desc request callback */
    } ESP_ZNSP_ZB_PACKED_STRUCT esp_zb_zdo_bind_desc_t;

    esp_zb_zdo_bind_desc_t *zdo_bind_desc = (esp_zb_zdo_bind_desc_t *)input;
    if (zdo_bind_desc->bind_usr.user_cb) {
        esp_zb_zdo_bind_callback_t zdo_bind_desc_callback = (esp_zb_zdo_bind_callback_t)zdo_bind_desc->bind_usr.user_cb;
        zdo_bind_desc_callback(zdo_bind_desc->zdo_status, (void *)zdo_bind_desc->bind_usr.user_ctx);
    }

    return ESP_OK;
}

static esp_err_t esp_host_zb_set_unbind_fn(const uint8_t *input, uint16_t inlen)
{
    typedef struct {
        esp_zb_zdp_status_t    zdo_status;
        esp_zb_user_cb_t       bind_usr;                   /*!< A ZDO bind desc request callback */
    } ESP_ZNSP_ZB_PACKED_STRUCT esp_zb_zdo_unbind_desc_t;

    esp_zb_zdo_unbind_desc_t *zdo_bind_desc = (esp_zb_zdo_unbind_desc_t *)input;
    if (zdo_bind_desc->bind_usr.user_cb) {
        esp_zb_zdo_bind_callback_t zdo_bind_desc_callback = (esp_zb_zdo_bind_callback_t)zdo_bind_desc->bind_usr.user_cb;
        zdo_bind_desc_callback(zdo_bind_desc->zdo_status, (void *)zdo_bind_desc->bind_usr.user_ctx);
    }

    return ESP_OK;
}

static esp_err_t esp_host_zb_find_match_fn(const uint8_t *input, uint16_t inlen)
{
    typedef struct {
        esp_zb_zdp_status_t zdo_status;
        uint16_t            addr;
        uint8_t             endpoint;
        esp_zb_user_cb_t    find_usr;
    } ESP_ZNSP_ZB_PACKED_STRUCT esp_zb_zdo_match_desc_t;

    esp_zb_zdo_match_desc_t *zdo_match_desc = (esp_zb_zdo_match_desc_t *)input;

    if (zdo_match_desc->find_usr.user_cb) {
        esp_zb_zdo_match_desc_callback_t zdo_match_desc_callback = (esp_zb_zdo_match_desc_callback_t)zdo_match_desc->find_usr.user_cb;
        zdo_match_desc_callback(zdo_match_desc->zdo_status, zdo_match_desc->addr, zdo_match_desc->endpoint, (void *)zdo_match_desc->find_usr.user_ctx);
    }

    return ESP_OK;
}

/* --- Active EP response notification handler --- */
static esp_err_t esp_host_zb_active_ep_fn(const uint8_t *input, uint16_t inlen)
{
    if (!input || inlen < 4) {
        return ESP_ERR_INVALID_ARG;
    }

    const uint8_t *p = input;
    uint8_t zdo_status = *p++;
    uint16_t addr;
    memcpy(&addr, p, sizeof(uint16_t));
    p += 2;
    uint8_t ep_count = *p++;
    const uint8_t *ep_list = p;
    p += ep_count;

    /* Extract user callback */
    if ((p + sizeof(esp_zb_user_cb_t)) <= (input + inlen)) {
        esp_zb_user_cb_t user_cb;
        memcpy(&user_cb, p, sizeof(esp_zb_user_cb_t));

        /* Validate callback pointer is in executable code range (0x40000000–0x4FFFFFFF) */
        if (user_cb.user_cb && (user_cb.user_cb & 0xF0000000) == 0x40000000) {
            esp_zb_zdo_active_ep_callback_t cb = (esp_zb_zdo_active_ep_callback_t)user_cb.user_cb;
            cb(zdo_status, ep_count, (uint8_t *)ep_list, (void *)user_cb.user_ctx);
        } else if (user_cb.user_cb) {
            ESP_LOGW("ESP_HOST_ZB", "Active EP: invalid callback ptr 0x%08x, skipping", (unsigned)user_cb.user_cb);
        }
    }

    return ESP_OK;
}

/* --- Simple Desc response notification handler --- */
static esp_err_t esp_host_zb_simple_desc_fn(const uint8_t *input, uint16_t inlen)
{
    if (!input || inlen < 3) {
        return ESP_ERR_INVALID_ARG;
    }

    const uint8_t *p = input;
    uint8_t zdo_status = *p++;
    uint16_t addr;
    memcpy(&addr, p, sizeof(uint16_t));
    p += 2;

    esp_zb_af_simple_desc_1_1_t simple_desc = {0};
    esp_zb_af_simple_desc_1_1_t *desc_ptr = NULL;

    if (zdo_status == 0 /* ESP_ZB_ZDP_STATUS_SUCCESS */ && (p + 8) <= (input + inlen)) {
        simple_desc.endpoint = *p++;
        memcpy(&simple_desc.app_profile_id, p, sizeof(uint16_t)); p += 2;
        memcpy(&simple_desc.app_device_id, p, sizeof(uint16_t)); p += 2;
        simple_desc.app_device_version = *p++;
        simple_desc.app_input_cluster_count = *p++;
        simple_desc.app_output_cluster_count = *p++;
        uint8_t total = simple_desc.app_input_cluster_count + simple_desc.app_output_cluster_count;
        if (total > 0 && (p + total * 2) <= (input + inlen)) {
            simple_desc.app_cluster_list = (uint16_t *)p;
            p += total * 2;
        }
        desc_ptr = &simple_desc;
    }

    /* Extract user callback at the end */
    if ((p + sizeof(esp_zb_user_cb_t)) <= (input + inlen)) {
        esp_zb_user_cb_t user_cb;
        memcpy(&user_cb, p, sizeof(esp_zb_user_cb_t));

        /* Validate callback pointer is in executable code range (0x40000000–0x4FFFFFFF) */
        if (user_cb.user_cb && (user_cb.user_cb & 0xF0000000) == 0x40000000) {
            esp_zb_zdo_simple_desc_callback_t cb = (esp_zb_zdo_simple_desc_callback_t)user_cb.user_cb;
            cb(zdo_status, desc_ptr, (void *)user_cb.user_ctx);
        } else if (user_cb.user_cb) {
            ESP_LOGW("ESP_HOST_ZB", "Simple desc: invalid callback ptr 0x%08x, skipping", (unsigned)user_cb.user_cb);
        }
    }

    return ESP_OK;
}

/* --- ZCL Attribute Report notification handler --- */
static esp_err_t esp_host_zb_zcl_attr_report_fn(const uint8_t *input, uint16_t inlen)
{
    if (!s_action_handler || !input) {
        return ESP_OK;
    }

    /* NCP sends: report_header + attr_header + attr_value
     * report_header = status(1) + src_address(esp_zb_zcl_addr_t) + src_ep(1) + dst_ep(1) + cluster(2)
     * attr_header = attr_id(2) + type(1) + size(1)
     * attr_value = size bytes
     */
    typedef struct {
        esp_zb_zcl_status_t status;
        esp_zb_zcl_addr_t src_address;
        uint8_t src_endpoint;
        uint8_t dst_endpoint;
        uint16_t cluster;
    } ESP_ZNSP_ZB_PACKED_STRUCT report_header_t;

    typedef struct {
        uint16_t id;
        uint8_t type;
        uint8_t size;
    } ESP_ZNSP_ZB_PACKED_STRUCT attr_header_t;

    if (inlen < sizeof(report_header_t) + sizeof(attr_header_t)) {
        return ESP_ERR_INVALID_SIZE;
    }

    const report_header_t *hdr = (const report_header_t *)input;
    const attr_header_t *attr = (const attr_header_t *)(input + sizeof(report_header_t));
    const void *value = (inlen > sizeof(report_header_t) + sizeof(attr_header_t))
                        ? (input + sizeof(report_header_t) + sizeof(attr_header_t))
                        : NULL;

    esp_zb_zcl_report_attr_message_t msg = {
        .status = hdr->status,
        .src_address = hdr->src_address,
        .src_endpoint = hdr->src_endpoint,
        .dst_endpoint = hdr->dst_endpoint,
        .cluster = hdr->cluster,
        .attribute = {
            .id = attr->id,
            .data = {
                .type = attr->type,
                .size = attr->size,
                .value = (void *)value,
            },
        },
    };

    s_action_handler(ESP_ZB_CORE_REPORT_ATTR_CB_ID, &msg);
    return ESP_OK;
}

/* --- ZCL Read Attribute Response notification handler --- */
static esp_err_t esp_host_zb_zcl_attr_read_fn(const uint8_t *input, uint16_t inlen)
{
    if (!s_action_handler || !input) {
        return ESP_OK;
    }

    /* NCP sends packed: status(1) + addr(9) + src_ep(1) + dst_ep(1) + cluster(2) + count(1) + attrs */
    typedef struct {
        esp_zb_zcl_status_t status;
        esp_zb_zcl_addr_t src_address;
        uint8_t src_endpoint;
        uint8_t dst_endpoint;
        uint16_t cluster;
    } ESP_ZNSP_ZB_PACKED_STRUCT read_resp_hdr_t;

    if (inlen < sizeof(read_resp_hdr_t) + 1) {
        return ESP_ERR_INVALID_SIZE;
    }

    const uint8_t *p = input;
    read_resp_hdr_t hdr;
    memcpy(&hdr, p, sizeof(read_resp_hdr_t));
    p += sizeof(read_resp_hdr_t);

    esp_zb_zcl_cmd_info_t info = {
        .status       = hdr.status,
        .src_address  = hdr.src_address,
        .src_endpoint = hdr.src_endpoint,
        .dst_endpoint = hdr.dst_endpoint,
        .cluster      = hdr.cluster,
    };

    uint8_t count = *p++;

    /* Build linked list of variables */
    esp_zb_zcl_read_attr_resp_variable_t *head = NULL;
    esp_zb_zcl_read_attr_resp_variable_t *tail = NULL;
    esp_zb_zcl_read_attr_resp_variable_t *vars = NULL;

    if (count > 0) {
        vars = calloc(count, sizeof(esp_zb_zcl_read_attr_resp_variable_t));
        if (!vars) {
            return ESP_ERR_NO_MEM;
        }
    }

    for (uint8_t i = 0; i < count; i++) {
        if ((p + 4) > (input + inlen)) break;

        uint16_t attr_id;
        memcpy(&attr_id, p, 2); p += 2;
        uint8_t type = *p++;
        uint8_t size = *p++;

        vars[i].attribute.id = attr_id;
        vars[i].attribute.data.type = type;
        vars[i].attribute.data.size = size;
        vars[i].attribute.data.value = (size > 0 && (p + size) <= (input + inlen)) ? (void *)p : NULL;
        vars[i].next = NULL;
        p += size;

        if (!head) {
            head = &vars[i];
        } else {
            tail->next = &vars[i];
        }
        tail = &vars[i];
    }

    esp_zb_zcl_cmd_read_attr_resp_message_t msg = {
        .info = info,
        .variables = head,
    };

    s_action_handler(ESP_ZB_CORE_CMD_READ_ATTR_RESP_CB_ID, &msg);

    if (vars) {
        free(vars);
    }

    return ESP_OK;
}

/* --- Stack status change notification handler --- */
static esp_err_t esp_host_zb_stack_status_fn(const uint8_t *input, uint16_t inlen)
{
    uint8_t status = (input && inlen >= 1) ? input[0] : 0xFF;
    ESP_LOGW(TAG, "NCP stack status change: 0x%02X (len=%u)", status, inlen);

    /* Status 0 typically means network is up/restored, non-zero may indicate
     * NCP restarted or lost network. Log for diagnostics — the watchdog will
     * handle actual recovery if the NCP becomes unresponsive. */
    return ESP_OK;
}

static const esp_host_zb_func_t host_zb_func_table[] = {
    {ESP_ZNSP_NETWORK_STACK_STATUS_HANDLER, esp_host_zb_stack_status_fn},
    {ESP_ZNSP_NETWORK_FORMNETWORK, esp_host_zb_form_network_fn},
    {ESP_ZNSP_NETWORK_JOINNETWORK, esp_host_zb_joining_network_fn},
    {ESP_ZNSP_NETWORK_PERMIT_JOINING, esp_host_zb_permit_joining_fn},
    {ESP_ZNSP_NETWORK_LEAVENETWORK, esp_host_zb_leave_network_fn},
    {ESP_ZNSP_ZDO_BIND_SET, esp_host_zb_set_bind_fn},
    {ESP_ZNSP_ZDO_UNBIND_SET, esp_host_zb_set_unbind_fn},
    {ESP_ZNSP_ZDO_FIND_MATCH, esp_host_zb_find_match_fn},
    {ESP_ZNSP_ZDO_ACTIVE_EP, esp_host_zb_active_ep_fn},
    {ESP_ZNSP_ZDO_SIMPLE_DESC, esp_host_zb_simple_desc_fn},
    {ESP_ZNSP_ZCL_ATTR_REPORT, esp_host_zb_zcl_attr_report_fn},
    {ESP_ZNSP_ZCL_ATTR_READ, esp_host_zb_zcl_attr_read_fn},
};

esp_err_t esp_host_zb_input(esp_host_header_t *host_header, const void *buffer, uint16_t len)
{
    QueueHandle_t queue = (host_header->flags.type == ESP_ZNSP_TYPE_NOTIFY) ? notify_queue : output_queue;
    BaseType_t ret = 0;
    esp_host_zb_ctx_t host_ctx = {
        .id = host_header->id,
        .size = len,
    };

    if (buffer && len > 0) {
        host_ctx.data = calloc(1, len);
        if (!host_ctx.data) {
            ESP_LOGE(TAG, "Failed to allocate %u bytes for ZNSP input", len);
            return ESP_ERR_NO_MEM;
        }
        memcpy(host_ctx.data, buffer, len);
    }

    if (xPortInIsrContext() == pdTRUE) {
        ret = xQueueSendFromISR(queue, &host_ctx, NULL);
    } else {
        ret = xQueueSend(queue, &host_ctx, 0);
    }
    if (ret != pdTRUE) {
        free(host_ctx.data);
        host_ctx.data = NULL;
        return ESP_FAIL;
    }
    return ESP_OK;
}

esp_err_t esp_host_zb_output(uint16_t id, const void *buffer, uint16_t len, void *output, uint16_t *outlen)
{
    esp_host_header_t data_header = {
        .id = id,
        .sn = esp_random() % 0xFF,
        .len = len,
        .flags = {
            .version = 0,
        }
    };
    data_header.flags.type = ESP_ZNSP_TYPE_REQUEST;

    xSemaphoreTakeRecursive(lock_semaphore, portMAX_DELAY);
    esp_host_frame_output(&data_header, buffer, len);

    esp_host_zb_ctx_t host_ctx;
    if (xQueueReceive(output_queue, &host_ctx, pdMS_TO_TICKS(5000)) != pdTRUE) {
        ESP_LOGE(TAG, "ZNSP timeout waiting for response to 0x%04X", id);
        /* Drain any stale responses that may arrive late */
        esp_host_zb_ctx_t stale;
        while (xQueueReceive(output_queue, &stale, 0) == pdTRUE) {
            ESP_LOGW(TAG, "Draining stale response 0x%04X after timeout", stale.id);
            free(stale.data);
        }
        xSemaphoreGiveRecursive(lock_semaphore);
        return ESP_ERR_TIMEOUT;
    }
    esp_err_t ret = ESP_OK;
    if (host_ctx.data) {
        if (host_ctx.id == id) {
            if (output && outlen) {
                uint16_t copy_len = (host_ctx.size < *outlen) ? host_ctx.size : *outlen;
                memcpy(output, host_ctx.data, copy_len);
                *outlen = copy_len;
            } else if (outlen) {
                *outlen = host_ctx.size;
            }
        } else {
            ESP_LOGW(TAG, "ZNSP response ID mismatch: expected 0x%04X, got 0x%04X", id, host_ctx.id);
            ret = ESP_ERR_INVALID_RESPONSE;
        }

        free(host_ctx.data);
        host_ctx.data = NULL;
    }
    xSemaphoreGiveRecursive(lock_semaphore);

    return ret;
}

void *esp_zb_app_signal_get_params(uint32_t *signal_p)
{
    esp_zb_app_signal_msg_t *app_signal_msg = (esp_zb_app_signal_msg_t *)signal_p;

    return app_signal_msg ? (void *)app_signal_msg->msg : (void *)app_signal_msg;
}

void esp_zb_stack_main_loop(void)
{
    esp_host_zb_ctx_t host_ctx;
    while (1) {
       if (xQueueReceive(notify_queue, &host_ctx, pdMS_TO_TICKS(100)) != pdTRUE) {
            continue;
       }

       bool handled = false;
       for (int i = 0; i < sizeof(host_zb_func_table) / sizeof(host_zb_func_table[0]); i++) {
            if (host_ctx.id != host_zb_func_table[i].id) {
                continue;
            }

            host_zb_func_table[i].set_func(host_ctx.data, host_ctx.size);
            handled = true;
            break;
        }
        if (!handled) {
            ESP_LOGW(TAG, "Unknown notification ID 0x%04X (size=%u), dropped", host_ctx.id, host_ctx.size);
        }

        if (host_ctx.data) {
            free(host_ctx.data);
            host_ctx.data = NULL;
        }
    }
}

void esp_zb_main_loop_iteration(void)
{
    esp_zb_stack_main_loop();
}

esp_err_t esp_zb_device_register(esp_zb_ep_list_t *ep_list)
{
    return ESP_OK;
}

esp_err_t esp_zb_platform_config(esp_zb_platform_config_t *config)
{
    ESP_ERROR_CHECK(esp_host_init(config->host_config.host_mode));
    ESP_ERROR_CHECK(esp_host_start());

    output_queue = xQueueCreate(HOST_EVENT_QUEUE_LEN, sizeof(esp_host_zb_ctx_t));
    notify_queue = xQueueCreate(HOST_EVENT_QUEUE_LEN, sizeof(esp_host_zb_ctx_t));
    lock_semaphore = xSemaphoreCreateRecursiveMutex();

    return ESP_OK;
}

/* --- Action handler registration --- */
void esp_zb_core_action_handler_register(esp_zb_core_action_handler_t cb)
{
    s_action_handler = cb;
}

/* --- Lock acquire/release using the existing recursive mutex --- */
bool esp_zb_lock_acquire(TickType_t block_ticks)
{
    if (!lock_semaphore) {
        return false;
    }
    return xSemaphoreTakeRecursive(lock_semaphore, block_ticks) == pdTRUE;
}

void esp_zb_lock_release(void)
{
    if (lock_semaphore) {
        xSemaphoreGiveRecursive(lock_semaphore);
    }
}

/* --- Scheduler alarm using FreeRTOS one-shot timer --- */
typedef struct {
    esp_zb_callback_t cb;
    uint8_t param;
} alarm_ctx_t;

static void alarm_timer_cb(TimerHandle_t timer)
{
    alarm_ctx_t *ctx = (alarm_ctx_t *)pvTimerGetTimerID(timer);
    if (ctx) {
        ctx->cb(ctx->param);
        free(ctx);
    }
    xTimerDelete(timer, 0);
}

void esp_zb_scheduler_alarm(esp_zb_callback_t cb, uint8_t param, uint32_t time)
{
    alarm_ctx_t *ctx = calloc(1, sizeof(alarm_ctx_t));
    if (!ctx) return;
    ctx->cb = cb;
    ctx->param = param;

    TimerHandle_t timer = xTimerCreate("zb_alarm", pdMS_TO_TICKS(time), pdFALSE, ctx, alarm_timer_cb);
    if (timer) {
        xTimerStart(timer, 0);
    } else {
        free(ctx);
    }
}

/* --- Open network (permit join) --- */
esp_err_t esp_zb_bdb_open_network(uint8_t duration)
{
    uint8_t output = 0;
    uint16_t outlen = sizeof(uint8_t);

    return esp_host_zb_output(ESP_ZNSP_NETWORK_PERMIT_JOINING, &duration, sizeof(uint8_t), &output, &outlen);
}

/* --- Factory new check --- */
/* Always returns false in NCP host mode: the host component never dispatches
 * DEVICE_FIRST_START/DEVICE_REBOOT signals — esp_zb_init() dispatches
 * SKIP_STARTUP, and form_network_fn dispatches FORMATION. So any
 * is_factory_new check in the signal handler is effectively dead code. */
bool esp_zb_bdb_is_factory_new(void)
{
    return false;
}

/* --- Security settings --- */
void esp_zb_secur_link_key_exchange_required_set(bool enable) { }
void esp_zb_secur_ic_only_enable(bool enable) { }
void esp_zb_secur_network_min_join_lqi_set(uint8_t lqi) { }

void esp_zb_secur_tcpol_set_allow_tc_rejoins(uint8_t allow)
{
    /* No-op on host side — TC rejoin policy is set on NCP in esp_zigbee_ncp.c app_main().
     * NCP SECURE_MODE_SET (0x002A) handler is a stub, SET_TC_POLICY (0x0032) doesn't exist. */
}

void esp_zb_secur_set_unsecure_tc_rejoin_enabled(bool enable)
{
    /* No-op on host side — configured on NCP directly via ZBOSS API. */
}

void esp_zb_set_trace_level_mask(uint32_t subsystem, uint32_t level) { }
