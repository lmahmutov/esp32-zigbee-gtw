#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "esp_zigbee_core.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#define MAX_DEVICES       CONFIG_GW_MAX_DEVICES
#define MAX_EP_PER_DEV    8
#define DEV_NAME_LEN      32

typedef struct {
    uint8_t  id;
    uint16_t profile_id;
    uint16_t device_id;
    bool     has_on_off;
    bool     on_off_state;
    bool     has_level;
    uint8_t  level;
    bool     has_temperature;
    int16_t  temperature;       /* x100 */
    bool     has_humidity;
    uint16_t humidity;          /* x100 */
    bool     has_pressure;
    int16_t  pressure;          /* hPa */
    bool     has_illuminance;
    uint16_t illuminance;
    bool     has_occupancy;
    uint8_t  occupancy;         /* 0=unoccupied, 1=occupied */
} dev_endpoint_t;

typedef struct {
    bool            in_use;
    uint16_t        short_addr;
    esp_zb_ieee_addr_t ieee_addr;
    char            name[DEV_NAME_LEN];
    uint8_t         ep_count;
    dev_endpoint_t  endpoints[MAX_EP_PER_DEV];
    char            manufacturer[32];  /* from Basic cluster attr 0x0004 */
    char            model[32];         /* from Basic cluster attr 0x0005 */
    uint8_t         lqi;
    int64_t         last_seen_sec;
    bool            discovery_done;
} zb_device_t;

void     device_list_init(void);
int      device_add(uint16_t short_addr, const esp_zb_ieee_addr_t ieee_addr);
int      device_find(uint16_t short_addr);
int      device_find_by_ieee(const esp_zb_ieee_addr_t ieee_addr);
void     device_remove(int idx);
int      device_count(void);
void     device_lock(void);
void     device_unlock(void);

/* Persist device list to NVS / restore from NVS */
void     device_list_save(void);
void     device_list_save_deferred(void);   /* Sets flag, actual save happens on timer */
void     device_list_save_timer_init(void);
void     device_list_load(void);

/* Direct access — caller must hold lock */
zb_device_t *device_get(int idx);
zb_device_t *device_get_all(void);
