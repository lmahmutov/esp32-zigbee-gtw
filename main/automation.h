#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define AUTO_MAX_SCRIPTS      16
#define AUTO_MAX_HANDLERS     64   /* total across all scripts */
#define AUTO_ID_LEN           40
#define AUTO_NAME_LEN         64
#define AUTO_EVENT_QUEUE_LEN  32

/* Event types dispatched to Lua handlers */
typedef enum {
    AUTO_EVT_PROPERTY_UPDATE = 0,
    AUTO_EVT_DEVICE_JOINED,
    AUTO_EVT_DEVICE_LEFT,
    AUTO_EVT_DEVICE_ANNOUNCE,
    AUTO_EVT_TIMER,            /* internal: zigbee.after() callback */
    AUTO_EVT_MAX
} auto_event_type_t;

/* Event payload (union for different event types) */
typedef struct {
    auto_event_type_t type;
    uint16_t short_addr;
    uint8_t  ieee[8];
    uint8_t  endpoint;
    uint16_t cluster;
    uint16_t attr_id;
    char     property[32];     /* "temperature", "on_off", etc. */
    union {
        int32_t  i;
        float    f;
        bool     b;
    } value;
    uint8_t  value_type;       /* 0=int, 1=float, 2=bool */
} auto_event_t;

/* Script metadata */
typedef struct {
    char id[AUTO_ID_LEN];
    char name[AUTO_NAME_LEN];
    bool enabled;
    bool running;              /* VM currently active */
} auto_script_meta_t;

/* Initialize automation engine (call after device_list_init, before zigbee_start) */
void automation_init(void);

/* Start all enabled scripts */
void automation_start(void);

/* Stop all scripts and free resources */
void automation_stop(void);

/* Dispatch an event to all running scripts */
void automation_dispatch_event(const auto_event_t *event);

/* Script management */
int  automation_list_scripts(auto_script_meta_t *out, int max_count);
bool automation_get_script(const char *id, char *lua_code, size_t code_sz,
                           char *blockly_xml, size_t xml_sz,
                           auto_script_meta_t *meta);
bool automation_save_script(const char *id, const char *name,
                            const char *lua_code, const char *blockly_xml,
                            bool enabled);
bool automation_delete_script(const char *id);
bool automation_toggle_script(const char *id);

/* Run a script once for testing (returns log output, caller frees) */
char *automation_run_test(const char *id);
char *automation_run_inline(const char *lua_code);

/* Register an event handler from Lua (called by lua_api.c) */
int automation_register_handler(int script_idx, auto_event_type_t type,
                                const char *filter_ieee,
                                const char *filter_property,
                                int lua_func_ref);

/* Post a timer event to a script's queue (called from FreeRTOS timer callback) */
void automation_post_timer_event(int script_idx, int func_ref);

/* Append to test log buffer (called by lua_api.c) */
void automation_test_log_append(const char *msg);
