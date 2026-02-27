#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"
#include "esp_zigbee_core.h"

/* ── Configuration ─────────────────────────────────────── */

#define GW_ENDPOINT                1
#define GW_MAX_CHILDREN            32
#define GW_INSTALLCODE_POLICY      false

/* Primary channel mask — all channels by default, or specific one from config */
#if CONFIG_GW_ZIGBEE_CHANNEL >= 11 && CONFIG_GW_ZIGBEE_CHANNEL <= 26
#define GW_CHANNEL_MASK            (1UL << CONFIG_GW_ZIGBEE_CHANNEL)
#else
#define GW_CHANNEL_MASK            ESP_ZB_TRANSCEIVER_ALL_CHANNELS_MASK
#endif

#define ESP_MANUFACTURER_NAME      "\x09""ESPRESSIF"
#define ESP_MODEL_IDENTIFIER       "\x07""ESP32S3"

#define ESP_ZB_ZC_CONFIG()                                  \
    {                                                       \
        .esp_zb_role = ESP_ZB_DEVICE_TYPE_COORDINATOR,      \
        .install_code_policy = GW_INSTALLCODE_POLICY,       \
        .nwk_cfg.zczr_cfg = {                               \
            .max_children = GW_MAX_CHILDREN,                \
        },                                                  \
    }

/* ── Public API ────────────────────────────────────────── */

typedef struct {
    bool     running;
    uint16_t pan_id;
    uint8_t  channel;
    uint16_t short_addr;
    int      device_count;
    bool     permit_join;
    uint8_t  permit_join_remaining;
} zigbee_status_t;

/* Call from app_main BEFORE zigbee_start() */
esp_err_t zigbee_platform_init(void);

/* Reset ESP32-H2 NCP into normal boot mode via GPIO7/GPIO8 */
esp_err_t zigbee_ncp_reset(void);

/* Create Zigbee task — non-blocking, returns immediately */
esp_err_t zigbee_start(void);

void      zigbee_get_status(zigbee_status_t *out);
void      zigbee_permit_join(uint8_t duration_sec);
void      zigbee_send_on_off(uint16_t addr, uint8_t endpoint, uint8_t cmd);
void      zigbee_read_attribute(uint16_t addr, uint8_t endpoint,
                                uint16_t cluster, uint16_t attr_id);

/* Change channel: saves to NVS, factory-resets Zigbee network, restarts.
   All devices will need to re-pair. channel must be 11..26 or 0 for auto. */
void      zigbee_set_channel(uint8_t channel);

/* Erase Zigbee NVRAM and restart — forces fresh network formation */
void      zigbee_factory_reset(void);

/* Start NCP watchdog — pings NCP every 30s, resets on 2 consecutive timeouts.
   Call after zigbee_start() completes. */
void      zigbee_ncp_watchdog_init(void);

/* Copy recent log output into buffer. Returns bytes written. */
size_t    zigbee_get_log(char *out, size_t max_len);
