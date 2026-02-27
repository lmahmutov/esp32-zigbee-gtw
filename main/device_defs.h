#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define MAX_DEVICE_DEFS   32
#define MAX_BIND_CLUSTERS 8
#define MAX_BIND_EPS      4

typedef struct {
    uint8_t  endpoint;
    uint8_t  cluster_count;
    uint16_t clusters[MAX_BIND_CLUSTERS];
} dev_def_bind_t;

typedef struct {
    char manufacturer[32];
    char model[32];
    uint8_t bind_count;
    dev_def_bind_t binds[MAX_BIND_EPS];
} device_def_t;

/* Initialize device definitions subsystem (mount SPIFFS if needed, load JSON) */
void device_defs_init(void);

/* Reload definitions from /storage/devices.json */
void device_defs_load(void);

/* Find definition for manufacturer+model. Copies result into *out. Returns true if found. */
bool device_defs_find(const char *manufacturer, const char *model, device_def_t *out);

/* Save JSON string to /storage/devices.json and reload. Returns 0 on success. */
int device_defs_save(const char *json_str, size_t len);

/* Read file into malloc'd buffer (caller frees). Returns NULL on error. */
char *device_defs_get_json(void);
