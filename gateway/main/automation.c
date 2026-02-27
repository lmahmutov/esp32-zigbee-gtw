#include "automation.h"
#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"

#include "esp_log.h"
#include "esp_spiffs.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/timers.h"

#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <dirent.h>

static const char *TAG = "auto";

/* ---- Script storage ---- */
#define SCRIPTS_DIR "/storage/scripts"
#define MAX_SCRIPT_SIZE 4096
#define MAX_BLOCKLY_SIZE 8192

/* ---- Event handler registered by zigbee.on() ---- */
typedef struct {
    uint8_t  script_idx;           /* index into s_scripts[] */
    auto_event_type_t event_type;
    char     filter_ieee[17];      /* "" = any */
    char     filter_property[32];  /* "" = any */
    int      lua_func_ref;         /* LUA_REGISTRYINDEX ref */
} event_handler_t;

/* ---- Per-script state ---- */
typedef struct {
    bool            in_use;
    char            id[AUTO_ID_LEN];
    char            name[AUTO_NAME_LEN];
    bool            enabled;
    lua_State      *L;
    TaskHandle_t    task_handle;
    QueueHandle_t   event_queue;
    bool            stop_requested;
} script_state_t;

static script_state_t s_scripts[AUTO_MAX_SCRIPTS];
static event_handler_t s_handlers[AUTO_MAX_HANDLERS];
static int s_handler_count = 0;
static SemaphoreHandle_t s_mutex;

/* Test-mode log capture */
static char *s_test_log_buf;
static size_t s_test_log_len;
static size_t s_test_log_cap;
static SemaphoreHandle_t s_test_log_mutex;

/* Forward declarations for Lua API registration */
extern void lua_api_register_zigbee(lua_State *L, int script_idx);
extern void lua_api_register_system(lua_State *L);

/* ---- Helpers ---- */

static void sandbox_lua_state(lua_State *L)
{
    /* Remove dangerous base functions */
    static const char *remove[] = {
        "loadfile", "dofile", "load", "loadstring",
        "rawget", "rawset", "rawequal", "rawlen",
        "collectgarbage", NULL
    };
    for (int i = 0; remove[i]; i++) {
        lua_pushnil(L);
        lua_setglobal(L, remove[i]);
    }
}

/* Custom Lua allocator with memory limit */
#define LUA_MEM_LIMIT (48 * 1024)  /* 48KB per script */

typedef struct {
    size_t used;
} lua_alloc_ctx_t;

static void *lua_limited_alloc(void *ud, void *ptr, size_t osize, size_t nsize)
{
    lua_alloc_ctx_t *ctx = (lua_alloc_ctx_t *)ud;
    if (nsize == 0) {
        ctx->used -= osize;
        free(ptr);
        return NULL;
    }
    if (ctx->used - osize + nsize > LUA_MEM_LIMIT) {
        return NULL;  /* allocation refused */
    }
    void *p = realloc(ptr, nsize);
    if (p) {
        ctx->used = ctx->used - osize + nsize;
    }
    return p;
}

/* Lua hook to limit CPU cycles */
static void lua_count_hook(lua_State *L, lua_Debug *ar)
{
    (void)ar;
    luaL_error(L, "script exceeded CPU limit");
}

static lua_State *create_script_vm(int script_idx)
{
    lua_alloc_ctx_t *alloc_ctx = calloc(1, sizeof(lua_alloc_ctx_t));
    if (!alloc_ctx) return NULL;

    lua_State *L = lua_newstate(lua_limited_alloc, alloc_ctx);
    if (!L) {
        free(alloc_ctx);
        return NULL;
    }

    luaL_openlibs(L);
    sandbox_lua_state(L);

    /* CPU limit: 100K instructions before hook fires */
    lua_sethook(L, lua_count_hook, LUA_MASKCOUNT, 100000);

    /* Register API modules */
    lua_api_register_zigbee(L, script_idx);
    lua_api_register_system(L);

    return L;
}

static void destroy_script_vm(int script_idx)
{
    script_state_t *s = &s_scripts[script_idx];
    if (!s->L) return;

    /* Remove all handlers for this script */
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    for (int i = s_handler_count - 1; i >= 0; i--) {
        if (s_handlers[i].script_idx == script_idx) {
            luaL_unref(s->L, LUA_REGISTRYINDEX, s_handlers[i].lua_func_ref);
            s_handlers[i] = s_handlers[--s_handler_count];
        }
    }
    xSemaphoreGive(s_mutex);

    /* Free allocator context */
    lua_Alloc alloc_func;
    void *ud;
    alloc_func = lua_getallocf(s->L, &ud);
    (void)alloc_func;

    lua_close(s->L);
    s->L = NULL;

    if (ud) free(ud);
}

/* ---- File I/O ---- */

static bool ensure_scripts_dir(void)
{
    struct stat st;
    if (stat(SCRIPTS_DIR, &st) != 0) {
        if (mkdir(SCRIPTS_DIR, 0755) != 0) {
            ESP_LOGE(TAG, "Failed to create %s", SCRIPTS_DIR);
            return false;
        }
    }
    return true;
}

/* Script file format:
 * Line 1: -- {"name":"...","enabled":true}
 * Lines 2+: --[[BLOCKLY_XML\n...\nBLOCKLY_XML]]--  (optional)
 * Rest: Lua code
 */
static bool load_script_file(const char *id, char *name, size_t name_sz,
                             bool *enabled, char *lua_code, size_t code_sz,
                             char *blockly_xml, size_t xml_sz)
{
    char path[80];
    snprintf(path, sizeof(path), SCRIPTS_DIR "/%s.lua", id);

    FILE *f = fopen(path, "r");
    if (!f) return false;

    /* Read metadata from first line */
    char line[256];
    if (fgets(line, sizeof(line), f)) {
        /* Parse "-- {"name":"...","enabled":...}" */
        char *json_start = strstr(line, "{");
        if (json_start) {
            /* Simple parse without cJSON to save code size */
            char *n = strstr(json_start, "\"name\":\"");
            if (n && name) {
                n += 8;
                char *end = strchr(n, '"');
                if (end) {
                    size_t len = end - n;
                    if (len >= name_sz) len = name_sz - 1;
                    memcpy(name, n, len);
                    name[len] = 0;
                }
            }
            if (enabled) {
                *enabled = strstr(json_start, "\"enabled\":true") != NULL;
            }
        }
    }

    /* Check for Blockly XML block */
    if (blockly_xml) blockly_xml[0] = 0;
    long code_start = ftell(f);
    if (fgets(line, sizeof(line), f)) {
        if (strstr(line, "--[[BLOCKLY_XML")) {
            /* Read Blockly XML until end marker */
            size_t xml_pos = 0;
            while (fgets(line, sizeof(line), f)) {
                if (strstr(line, "BLOCKLY_XML]]--")) break;
                if (blockly_xml && xml_pos + strlen(line) < xml_sz - 1) {
                    strcpy(blockly_xml + xml_pos, line);
                    xml_pos += strlen(line);
                }
            }
            if (blockly_xml) blockly_xml[xml_pos] = 0;
            code_start = ftell(f);
        } else {
            /* No Blockly block, rewind */
            fseek(f, code_start, SEEK_SET);
        }
    }

    /* Read Lua code */
    if (lua_code) {
        size_t pos = 0;
        while (fgets(line, sizeof(line), f)) {
            size_t len = strlen(line);
            if (pos + len >= code_sz - 1) break;
            memcpy(lua_code + pos, line, len);
            pos += len;
        }
        lua_code[pos] = 0;
    }

    fclose(f);
    return true;
}

static bool save_script_file(const char *id, const char *name,
                             const char *lua_code, const char *blockly_xml,
                             bool enabled)
{
    if (!ensure_scripts_dir()) return false;

    char path[80];
    snprintf(path, sizeof(path), SCRIPTS_DIR "/%s.lua", id);

    FILE *f = fopen(path, "w");
    if (!f) {
        ESP_LOGE(TAG, "Failed to write %s", path);
        return false;
    }

    fprintf(f, "-- {\"name\":\"%s\",\"enabled\":%s}\n",
            name ? name : id,
            enabled ? "true" : "false");

    if (blockly_xml && blockly_xml[0]) {
        fprintf(f, "--[[BLOCKLY_XML\n%s\nBLOCKLY_XML]]--\n", blockly_xml);
    }

    if (lua_code) {
        fputs(lua_code, f);
        /* Ensure trailing newline */
        size_t len = strlen(lua_code);
        if (len > 0 && lua_code[len - 1] != '\n') {
            fputc('\n', f);
        }
    }

    fclose(f);
    return true;
}

static bool delete_script_file(const char *id)
{
    char path[80];
    snprintf(path, sizeof(path), SCRIPTS_DIR "/%s.lua", id);
    return remove(path) == 0;
}

/* ---- Script task ---- */

static void push_event_table(lua_State *L, const auto_event_t *evt)
{
    lua_createtable(L, 0, 8);

    static const char *type_names[] = {
        "property_update", "device_joined", "device_left", "device_announce"
    };
    if (evt->type < sizeof(type_names) / sizeof(type_names[0])) {
        lua_pushstring(L, type_names[evt->type]);
        lua_setfield(L, -2, "type");
    }

    /* IEEE as hex string */
    char ieee_str[24];
    snprintf(ieee_str, sizeof(ieee_str), "%02x%02x%02x%02x%02x%02x%02x%02x",
             evt->ieee[7], evt->ieee[6], evt->ieee[5], evt->ieee[4],
             evt->ieee[3], evt->ieee[2], evt->ieee[1], evt->ieee[0]);
    lua_pushstring(L, ieee_str);
    lua_setfield(L, -2, "ieee");

    lua_pushinteger(L, evt->short_addr);
    lua_setfield(L, -2, "short_addr");

    if (evt->type == AUTO_EVT_PROPERTY_UPDATE) {
        lua_pushstring(L, evt->property);
        lua_setfield(L, -2, "property");

        lua_pushinteger(L, evt->endpoint);
        lua_setfield(L, -2, "endpoint");
        lua_pushinteger(L, evt->cluster);
        lua_setfield(L, -2, "cluster");

        switch (evt->value_type) {
        case 0: lua_pushinteger(L, evt->value.i); break;
        case 1: lua_pushnumber(L, evt->value.f); break;
        case 2: lua_pushboolean(L, evt->value.b); break;
        default: lua_pushnil(L); break;
        }
        lua_setfield(L, -2, "value");
    }
}

static void script_task(void *arg)
{
    int idx = (int)(intptr_t)arg;
    script_state_t *s = &s_scripts[idx];
    auto_event_t evt;

    ESP_LOGI(TAG, "Script '%s' started", s->id);

    /* Load and execute the Lua code (registers handlers via zigbee.on()) */
    char *lua_code = malloc(MAX_SCRIPT_SIZE);
    if (!lua_code) {
        ESP_LOGE(TAG, "OOM loading script '%s'", s->id);
        goto done;
    }

    char name[AUTO_NAME_LEN];
    bool enabled;
    if (!load_script_file(s->id, name, sizeof(name), &enabled, lua_code, MAX_SCRIPT_SIZE, NULL, 0)) {
        ESP_LOGE(TAG, "Failed to load script '%s'", s->id);
        free(lua_code);
        goto done;
    }

    /* Reset CPU hook counter for initial load */
    lua_sethook(s->L, lua_count_hook, LUA_MASKCOUNT, 1000000);

    int err = luaL_dostring(s->L, lua_code);
    free(lua_code);

    if (err) {
        ESP_LOGE(TAG, "Script '%s' error: %s", s->id, lua_tostring(s->L, -1));
        lua_pop(s->L, 1);
        goto done;
    }

    /* Set tighter CPU limit for event handlers */
    lua_sethook(s->L, lua_count_hook, LUA_MASKCOUNT, 100000);

    /* Event loop */
    while (!s->stop_requested) {
        if (xQueueReceive(s->event_queue, &evt, pdMS_TO_TICKS(100)) != pdTRUE) {
            continue;
        }

        /* Handle timer callbacks (zigbee.after()) */
        if (evt.type == AUTO_EVT_TIMER) {
            lua_rawgeti(s->L, LUA_REGISTRYINDEX, evt.value.i);
            if (lua_isfunction(s->L, -1)) {
                if (lua_pcall(s->L, 0, 0, 0) != LUA_OK) {
                    ESP_LOGW(TAG, "zigbee.after() error in '%s': %s", s->id,
                             lua_tostring(s->L, -1));
                    lua_pop(s->L, 1);
                }
            } else {
                lua_pop(s->L, 1);
            }
            luaL_unref(s->L, LUA_REGISTRYINDEX, evt.value.i);
            continue;
        }

        /* Find matching handlers for this script */
        xSemaphoreTake(s_mutex, portMAX_DELAY);
        for (int i = 0; i < s_handler_count; i++) {
            event_handler_t *h = &s_handlers[i];
            if (h->script_idx != idx) continue;
            if (h->event_type != evt.type) continue;

            /* Filter by IEEE */
            if (h->filter_ieee[0]) {
                char evt_ieee[24];
                snprintf(evt_ieee, sizeof(evt_ieee), "%02x%02x%02x%02x%02x%02x%02x%02x",
                         evt.ieee[7], evt.ieee[6], evt.ieee[5], evt.ieee[4],
                         evt.ieee[3], evt.ieee[2], evt.ieee[1], evt.ieee[0]);
                if (strcasecmp(h->filter_ieee, evt_ieee) != 0) continue;
            }

            /* Filter by property */
            if (h->filter_property[0]) {
                if (strcmp(h->filter_property, evt.property) != 0) continue;
            }

            /* Call the Lua handler function */
            lua_rawgeti(s->L, LUA_REGISTRYINDEX, h->lua_func_ref);
            push_event_table(s->L, &evt);
            xSemaphoreGive(s_mutex);

            if (lua_pcall(s->L, 1, 0, 0) != LUA_OK) {
                ESP_LOGW(TAG, "Handler error in '%s': %s", s->id,
                         lua_tostring(s->L, -1));
                lua_pop(s->L, 1);
            }

            goto next_event;  /* handlers already processed */
        }
        xSemaphoreGive(s_mutex);
next_event:;
    }

done:
    ESP_LOGI(TAG, "Script '%s' stopped", s->id);
    s->task_handle = NULL;
    vTaskDelete(NULL);
}

/* ---- Script lifecycle ---- */

static int find_script_slot(const char *id)
{
    for (int i = 0; i < AUTO_MAX_SCRIPTS; i++) {
        if (s_scripts[i].in_use && strcmp(s_scripts[i].id, id) == 0)
            return i;
    }
    return -1;
}

static int find_free_slot(void)
{
    for (int i = 0; i < AUTO_MAX_SCRIPTS; i++) {
        if (!s_scripts[i].in_use) return i;
    }
    return -1;
}

static void start_script(int idx)
{
    script_state_t *s = &s_scripts[idx];
    if (s->task_handle) return;  /* already running */

    s->L = create_script_vm(idx);
    if (!s->L) {
        ESP_LOGE(TAG, "Failed to create VM for '%s'", s->id);
        return;
    }

    s->event_queue = xQueueCreate(AUTO_EVENT_QUEUE_LEN, sizeof(auto_event_t));
    if (!s->event_queue) {
        destroy_script_vm(idx);
        ESP_LOGE(TAG, "Failed to create queue for '%s'", s->id);
        return;
    }

    s->stop_requested = false;

    char task_name[16];
    snprintf(task_name, sizeof(task_name), "lua_%d", idx);
    BaseType_t ret = xTaskCreate(script_task, task_name, 6144,
                                 (void *)(intptr_t)idx, 3, &s->task_handle);
    if (ret != pdPASS) {
        vQueueDelete(s->event_queue);
        s->event_queue = NULL;
        destroy_script_vm(idx);
        ESP_LOGE(TAG, "Failed to create task for '%s'", s->id);
    }
}

static void stop_script(int idx)
{
    script_state_t *s = &s_scripts[idx];
    if (!s->task_handle) return;

    s->stop_requested = true;

    /* Wait for task to exit */
    for (int i = 0; i < 50 && s->task_handle; i++) {
        vTaskDelay(pdMS_TO_TICKS(100));
    }

    if (s->task_handle) {
        ESP_LOGW(TAG, "Force-deleting task for '%s'", s->id);
        vTaskDelete(s->task_handle);
        s->task_handle = NULL;
    }

    destroy_script_vm(idx);

    /* Delete queue under mutex — prevents timer callbacks from using deleted handle */
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    if (s->event_queue) {
        vQueueDelete(s->event_queue);
        s->event_queue = NULL;
    }
    xSemaphoreGive(s_mutex);
}

/* ---- Public API ---- */

void automation_init(void)
{
    s_mutex = xSemaphoreCreateMutex();
    s_test_log_mutex = xSemaphoreCreateRecursiveMutex();
    memset(s_scripts, 0, sizeof(s_scripts));
    memset(s_handlers, 0, sizeof(s_handlers));
    s_handler_count = 0;
    ensure_scripts_dir();
    ESP_LOGI(TAG, "Automation engine initialized");
}

void automation_start(void)
{
    DIR *dir = opendir(SCRIPTS_DIR);
    if (!dir) {
        ESP_LOGW(TAG, "No scripts directory");
        return;
    }

    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        /* Match *.lua files */
        size_t len = strlen(ent->d_name);
        if (len < 5 || strcmp(ent->d_name + len - 4, ".lua") != 0)
            continue;

        /* Extract ID (filename without .lua) */
        char id[AUTO_ID_LEN];
        size_t id_len = len - 4;
        if (id_len >= AUTO_ID_LEN) id_len = AUTO_ID_LEN - 1;
        memcpy(id, ent->d_name, id_len);
        id[id_len] = 0;

        /* Load metadata */
        char name[AUTO_NAME_LEN];
        bool enabled = false;
        if (!load_script_file(id, name, sizeof(name), &enabled, NULL, 0, NULL, 0))
            continue;

        if (!enabled) {
            ESP_LOGI(TAG, "Script '%s' disabled, skipping", id);
            continue;
        }

        int slot = find_free_slot();
        if (slot < 0) {
            ESP_LOGW(TAG, "Max scripts reached, skipping '%s'", id);
            break;
        }

        script_state_t *s = &s_scripts[slot];
        s->in_use = true;
        strlcpy(s->id, id, AUTO_ID_LEN);
        strlcpy(s->name, name, AUTO_NAME_LEN);
        s->enabled = true;

        start_script(slot);
    }
    closedir(dir);
}

void automation_stop(void)
{
    for (int i = 0; i < AUTO_MAX_SCRIPTS; i++) {
        if (s_scripts[i].in_use && s_scripts[i].task_handle) {
            stop_script(i);
        }
    }
}

void automation_post_timer_event(int script_idx, int func_ref)
{
    if (script_idx < 0 || script_idx >= AUTO_MAX_SCRIPTS) return;

    if (xSemaphoreTake(s_mutex, pdMS_TO_TICKS(100)) != pdTRUE) return;

    script_state_t *s = &s_scripts[script_idx];
    if (s->in_use && s->event_queue && !s->stop_requested) {
        auto_event_t evt = {0};
        evt.type = AUTO_EVT_TIMER;
        evt.value.i = func_ref;
        xQueueSend(s->event_queue, &evt, 0);
    }

    xSemaphoreGive(s_mutex);
}

void automation_dispatch_event(const auto_event_t *event)
{
    if (xSemaphoreTake(s_mutex, pdMS_TO_TICKS(50)) != pdTRUE) return;

    for (int i = 0; i < AUTO_MAX_SCRIPTS; i++) {
        script_state_t *s = &s_scripts[i];
        if (!s->in_use || !s->event_queue || !s->task_handle)
            continue;

        /* Non-blocking send — drop if full */
        if (xQueueSend(s->event_queue, event, 0) != pdTRUE) {
            ESP_LOGW(TAG, "Event queue full for '%s', dropping", s->id);
        }
    }

    xSemaphoreGive(s_mutex);
}

int automation_list_scripts(auto_script_meta_t *out, int max_count)
{
    DIR *dir = opendir(SCRIPTS_DIR);
    if (!dir) return 0;

    int count = 0;
    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL && count < max_count) {
        size_t len = strlen(ent->d_name);
        if (len < 5 || strcmp(ent->d_name + len - 4, ".lua") != 0)
            continue;

        auto_script_meta_t *m = &out[count];
        size_t id_len = len - 4;
        if (id_len >= AUTO_ID_LEN) id_len = AUTO_ID_LEN - 1;
        memcpy(m->id, ent->d_name, id_len);
        m->id[id_len] = 0;

        m->name[0] = 0;
        m->enabled = false;
        load_script_file(m->id, m->name, AUTO_NAME_LEN, &m->enabled, NULL, 0, NULL, 0);
        if (!m->name[0]) strlcpy(m->name, m->id, AUTO_NAME_LEN);

        int idx = find_script_slot(m->id);
        m->running = (idx >= 0 && s_scripts[idx].task_handle != NULL);
        count++;
    }
    closedir(dir);
    return count;
}

bool automation_get_script(const char *id, char *lua_code, size_t code_sz,
                           char *blockly_xml, size_t xml_sz,
                           auto_script_meta_t *meta)
{
    char name[AUTO_NAME_LEN] = {0};
    bool enabled = false;

    if (!load_script_file(id, name, sizeof(name), &enabled,
                          lua_code, code_sz, blockly_xml, xml_sz))
        return false;

    if (meta) {
        strlcpy(meta->id, id, AUTO_ID_LEN);
        strlcpy(meta->name, name, AUTO_NAME_LEN);
        meta->enabled = enabled;
        int idx = find_script_slot(id);
        meta->running = (idx >= 0 && s_scripts[idx].task_handle != NULL);
    }
    return true;
}

bool automation_save_script(const char *id, const char *name,
                            const char *lua_code, const char *blockly_xml,
                            bool enabled)
{
    if (!id || !id[0]) return false;

    /* Validate ID: no slashes, dots-only, too long */
    if (strchr(id, '/') || strchr(id, '\\') || strcmp(id, ".") == 0 ||
        strcmp(id, "..") == 0 || strlen(id) >= AUTO_ID_LEN)
        return false;

    /* Stop running script if exists */
    int idx = find_script_slot(id);
    if (idx >= 0) {
        stop_script(idx);
    }

    if (!save_script_file(id, name, lua_code, blockly_xml, enabled))
        return false;

    /* Restart if enabled */
    if (enabled) {
        xSemaphoreTake(s_mutex, portMAX_DELAY);
        if (idx < 0) {
            idx = find_free_slot();
            if (idx < 0) { xSemaphoreGive(s_mutex); return true; }
            s_scripts[idx].in_use = true;
        }
        script_state_t *s = &s_scripts[idx];
        strlcpy(s->id, id, AUTO_ID_LEN);
        strlcpy(s->name, name ? name : id, AUTO_NAME_LEN);
        s->enabled = true;
        xSemaphoreGive(s_mutex);
        start_script(idx);
    } else if (idx >= 0) {
        xSemaphoreTake(s_mutex, portMAX_DELAY);
        s_scripts[idx].enabled = false;
        xSemaphoreGive(s_mutex);
    }

    return true;
}

bool automation_delete_script(const char *id)
{
    int idx = find_script_slot(id);
    if (idx >= 0) {
        stop_script(idx);
        xSemaphoreTake(s_mutex, portMAX_DELAY);
        s_scripts[idx].in_use = false;
        xSemaphoreGive(s_mutex);
    }
    return delete_script_file(id);
}

bool automation_toggle_script(const char *id)
{
    char name[AUTO_NAME_LEN] = {0};
    bool enabled = false;
    char *lua_code = malloc(MAX_SCRIPT_SIZE);
    char *blockly_xml = malloc(MAX_BLOCKLY_SIZE);
    if (!lua_code || !blockly_xml) {
        free(lua_code);
        free(blockly_xml);
        return false;
    }

    if (!load_script_file(id, name, sizeof(name), &enabled,
                          lua_code, MAX_SCRIPT_SIZE,
                          blockly_xml, MAX_BLOCKLY_SIZE)) {
        free(lua_code);
        free(blockly_xml);
        return false;
    }

    enabled = !enabled;
    bool ok = automation_save_script(id, name, lua_code, blockly_xml, enabled);
    free(lua_code);
    free(blockly_xml);
    return ok;
}

/* ---- Test execution ---- */

void automation_test_log_append(const char *msg)
{
    xSemaphoreTakeRecursive(s_test_log_mutex, portMAX_DELAY);
    if (s_test_log_buf) {
        size_t mlen = strlen(msg);
        if (s_test_log_len + mlen + 2 < s_test_log_cap) {
            memcpy(s_test_log_buf + s_test_log_len, msg, mlen);
            s_test_log_len += mlen;
            s_test_log_buf[s_test_log_len++] = '\n';
            s_test_log_buf[s_test_log_len] = 0;
        }
    }
    xSemaphoreGiveRecursive(s_test_log_mutex);
}

static char *run_lua_code(const char *code)
{
    /* Serialize concurrent test runs — recursive mutex allows
       automation_test_log_append() to re-enter during Lua execution */
    xSemaphoreTakeRecursive(s_test_log_mutex, portMAX_DELAY);

    /* Allocate log buffer */
    s_test_log_cap = 2048;
    s_test_log_buf = malloc(s_test_log_cap);
    if (!s_test_log_buf) { xSemaphoreGiveRecursive(s_test_log_mutex); return NULL; }
    s_test_log_buf[0] = 0;
    s_test_log_len = 0;

    lua_alloc_ctx_t *alloc_ctx = calloc(1, sizeof(lua_alloc_ctx_t));
    if (!alloc_ctx) { free(s_test_log_buf); s_test_log_buf = NULL; xSemaphoreGiveRecursive(s_test_log_mutex); return NULL; }

    lua_State *L = lua_newstate(lua_limited_alloc, alloc_ctx);
    if (!L) { free(alloc_ctx); free(s_test_log_buf); s_test_log_buf = NULL; xSemaphoreGiveRecursive(s_test_log_mutex); return NULL; }

    luaL_openlibs(L);
    sandbox_lua_state(L);
    lua_sethook(L, lua_count_hook, LUA_MASKCOUNT, 100000);
    lua_api_register_zigbee(L, -1);  /* -1 = test mode, no event registration */
    lua_api_register_system(L);

    int err = luaL_dostring(L, code);
    if (err) {
        const char *errmsg = lua_tostring(L, -1);
        automation_test_log_append(errmsg ? errmsg : "unknown error");
    }

    lua_Alloc af;
    void *ud;
    af = lua_getallocf(L, &ud);
    (void)af;
    lua_close(L);
    if (ud) free(ud);

    char *result = s_test_log_buf;
    s_test_log_buf = NULL;
    xSemaphoreGiveRecursive(s_test_log_mutex);
    return result;
}

char *automation_run_test(const char *id)
{
    char *lua_code = malloc(MAX_SCRIPT_SIZE);
    if (!lua_code) return NULL;

    if (!load_script_file(id, NULL, 0, NULL, lua_code, MAX_SCRIPT_SIZE, NULL, 0)) {
        free(lua_code);
        return NULL;
    }

    char *result = run_lua_code(lua_code);
    free(lua_code);
    return result;
}

char *automation_run_inline(const char *lua_code)
{
    return run_lua_code(lua_code);
}

/* ---- Handler registration (called from Lua API) ---- */

int automation_register_handler(int script_idx, auto_event_type_t type,
                                const char *filter_ieee,
                                const char *filter_property,
                                int lua_func_ref)
{
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    if (s_handler_count >= AUTO_MAX_HANDLERS) {
        xSemaphoreGive(s_mutex);
        return -1;
    }
    event_handler_t *h = &s_handlers[s_handler_count++];
    h->script_idx = script_idx;
    h->event_type = type;
    strlcpy(h->filter_ieee, filter_ieee ? filter_ieee : "", sizeof(h->filter_ieee));
    strlcpy(h->filter_property, filter_property ? filter_property : "", sizeof(h->filter_property));
    h->lua_func_ref = lua_func_ref;
    xSemaphoreGive(s_mutex);
    return 0;
}
