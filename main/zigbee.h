#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"
#include "esp_zigbee_core.h"

/* ── Configuration ─────────────────────────────────────── */

#define GW_ENDPOINT                1
#define GW_MAX_CHILDREN            32
#define GW_INSTALLCODE_POLICY      false

#define RCP_VERSION_MAX_SIZE       80

#define HOST_RESET_PIN_TO_RCP      CONFIG_PIN_TO_RCP_RESET
#define HOST_BOOT_PIN_TO_RCP       CONFIG_PIN_TO_RCP_BOOT
#define HOST_RX_PIN_TO_RCP_TX      CONFIG_PIN_TO_RCP_TX
#define HOST_TX_PIN_TO_RCP_RX      CONFIG_PIN_TO_RCP_RX

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

#define ESP_ZB_DEFAULT_RADIO_CONFIG()                       \
    {                                                       \
        .radio_mode = ZB_RADIO_MODE_UART_RCP,               \
        .radio_uart_config = {                              \
            .port = 1,                                      \
            .uart_config = {                                \
                .baud_rate  = 460800,                       \
                .data_bits  = UART_DATA_8_BITS,             \
                .parity     = UART_PARITY_DISABLE,          \
                .stop_bits  = UART_STOP_BITS_1,             \
                .flow_ctrl  = UART_HW_FLOWCTRL_DISABLE,     \
                .rx_flow_ctrl_thresh = 0,                   \
                .source_clk = UART_SCLK_DEFAULT,            \
            },                                              \
            .rx_pin = HOST_RX_PIN_TO_RCP_TX,                \
            .tx_pin = HOST_TX_PIN_TO_RCP_RX,                \
        },                                                  \
    }

#define ESP_ZB_DEFAULT_HOST_CONFIG()                        \
    {                                                       \
        .host_connection_mode = ZB_HOST_CONNECTION_MODE_NONE, \
    }

#define ESP_ZB_RCP_UPDATE_CONFIG()                          \
    {                                                       \
        .rcp_type = RCP_TYPE_ESP32H2_UART,                  \
        .uart_rx_pin = HOST_RX_PIN_TO_RCP_TX,              \
        .uart_tx_pin = HOST_TX_PIN_TO_RCP_RX,              \
        .uart_port = 1,                                     \
        .uart_baudrate = 115200,                            \
        .reset_pin = HOST_RESET_PIN_TO_RCP,                \
        .boot_pin  = HOST_BOOT_PIN_TO_RCP,                 \
        .update_baudrate = 460800,                          \
        .firmware_dir = "/rcp_fw/ot_rcp",                   \
        .target_chip = ESP32H2_CHIP,                        \
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

/* Initialize RCP update subsystem (call after SPIFFS mount) */
esp_err_t zigbee_rcp_update_init(void);

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

/* Copy recent log output into buffer. Returns bytes written. */
size_t    zigbee_get_log(char *out, size_t max_len);
