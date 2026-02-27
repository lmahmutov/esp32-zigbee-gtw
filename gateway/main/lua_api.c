#include "lua_api.h"
#include "automation.h"
#include "device_list.h"
#include "zigbee.h"

#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/timers.h"

#include <string.h>
#include <time.h>
#include <sys/time.h>

static const char *TAG = "lua_api";

/* Key for script_idx stored in Lua registry */
#define SCRIPT_IDX_KEY "___script_idx"

static int get_script_idx(lua_State *L)
{
    lua_getfield(L, LUA_REGISTRYINDEX, SCRIPT_IDX_KEY);
    int idx = (int)lua_tointeger(L, -1);
    lua_pop(L, 1);
    return idx;
}

/* ---- Device resolution: by IEEE hex string or by name ---- */

static int find_device_by_id(const char *id, uint16_t *out_addr)
{
    device_lock();
    zb_device_t *all = device_get_all();
    int count = device_count();

    for (int i = 0; i < CONFIG_GW_MAX_DEVICES && count > 0; i++) {
        zb_device_t *d = &all[i];
        if (!d->in_use) continue;
        count--;

        /* Match by IEEE hex string */
        char ieee_str[24];
        snprintf(ieee_str, sizeof(ieee_str), "%02x%02x%02x%02x%02x%02x%02x%02x",
                 d->ieee_addr[7], d->ieee_addr[6], d->ieee_addr[5], d->ieee_addr[4],
                 d->ieee_addr[3], d->ieee_addr[2], d->ieee_addr[1], d->ieee_addr[0]);
        if (strcasecmp(ieee_str, id) == 0) {
            *out_addr = d->short_addr;
            device_unlock();
            return i;
        }

        /* Match by name */
        if (d->name[0] && strcasecmp(d->name, id) == 0) {
            *out_addr = d->short_addr;
            device_unlock();
            return i;
        }
    }
    device_unlock();
    return -1;
}

/* Find first endpoint with given cluster */
static int find_endpoint_with_cluster(zb_device_t *d, uint16_t cluster_id)
{
    for (int i = 0; i < d->ep_count; i++) {
        dev_endpoint_t *ep = &d->endpoints[i];
        switch (cluster_id) {
        case 0x0006: if (ep->has_on_off)       return ep->id; break;
        case 0x0008: if (ep->has_level)        return ep->id; break;
        case 0x0402: if (ep->has_temperature)  return ep->id; break;
        case 0x0405: if (ep->has_humidity)     return ep->id; break;
        case 0x0403: if (ep->has_pressure)     return ep->id; break;
        case 0x0400: if (ep->has_illuminance)  return ep->id; break;
        case 0x0406: if (ep->has_occupancy)    return ep->id; break;
        }
    }
    /* Fallback to first endpoint */
    return (d->ep_count > 0) ? d->endpoints[0].id : 1;
}

/* ================================================================
 *  zigbee.on(event_type, filter, callback)
 * ================================================================ */

static int l_zigbee_on(lua_State *L)
{
    int script_idx = get_script_idx(L);
    if (script_idx < 0) {
        return luaL_error(L, "zigbee.on() not available in test mode");
    }

    const char *type_str = luaL_checkstring(L, 1);
    luaL_checktype(L, 2, LUA_TTABLE);
    luaL_checktype(L, 3, LUA_TFUNCTION);

    /* Map event type string */
    auto_event_type_t etype;
    if (strcmp(type_str, "property_update") == 0)       etype = AUTO_EVT_PROPERTY_UPDATE;
    else if (strcmp(type_str, "device_joined") == 0)    etype = AUTO_EVT_DEVICE_JOINED;
    else if (strcmp(type_str, "device_left") == 0)      etype = AUTO_EVT_DEVICE_LEFT;
    else if (strcmp(type_str, "device_announce") == 0)   etype = AUTO_EVT_DEVICE_ANNOUNCE;
    else return luaL_error(L, "unknown event type: %s", type_str);

    /* Extract filters from table */
    char filter_ieee[17] = {0};
    char filter_property[32] = {0};

    lua_getfield(L, 2, "ieee");
    if (lua_isstring(L, -1)) {
        strlcpy(filter_ieee, lua_tostring(L, -1), sizeof(filter_ieee));
    }
    lua_pop(L, 1);

    lua_getfield(L, 2, "property");
    if (lua_isstring(L, -1)) {
        strlcpy(filter_property, lua_tostring(L, -1), sizeof(filter_property));
    }
    lua_pop(L, 1);

    /* Store callback function reference */
    lua_pushvalue(L, 3);
    int ref = luaL_ref(L, LUA_REGISTRYINDEX);

    if (automation_register_handler(script_idx, etype, filter_ieee, filter_property, ref) < 0) {
        luaL_unref(L, LUA_REGISTRYINDEX, ref);
        return luaL_error(L, "max handlers reached");
    }

    return 0;
}

/* ================================================================
 *  zigbee.turn_on(device) / turn_off(device) / toggle(device)
 * ================================================================ */

static int l_zigbee_onoff(lua_State *L, uint8_t cmd)
{
    const char *id = luaL_checkstring(L, 1);
    uint16_t addr;
    int idx = find_device_by_id(id, &addr);
    if (idx < 0) {
        ESP_LOGW(TAG, "Device not found: %s", id);
        return 0;
    }

    device_lock();
    zb_device_t *d = device_get(idx);
    int ep = find_endpoint_with_cluster(d, 0x0006);
    device_unlock();

    zigbee_send_on_off(addr, ep, cmd);
    return 0;
}

static int l_zigbee_turn_on(lua_State *L)  { return l_zigbee_onoff(L, 1); }
static int l_zigbee_turn_off(lua_State *L) { return l_zigbee_onoff(L, 0); }
static int l_zigbee_toggle(lua_State *L)   { return l_zigbee_onoff(L, 2); }

/* ================================================================
 *  zigbee.get_property(device, property)
 * ================================================================ */

static int l_zigbee_get_property(lua_State *L)
{
    const char *id = luaL_checkstring(L, 1);
    const char *prop = luaL_checkstring(L, 2);

    uint16_t addr;
    int idx = find_device_by_id(id, &addr);
    if (idx < 0) {
        lua_pushnil(L);
        return 1;
    }

    device_lock();
    zb_device_t *d = device_get(idx);

    /* Search all endpoints for the property */
    bool found = false;
    for (int i = 0; i < d->ep_count && !found; i++) {
        dev_endpoint_t *ep = &d->endpoints[i];

        if (strcmp(prop, "on_off") == 0 && ep->has_on_off) {
            lua_pushboolean(L, ep->on_off_state);
            found = true;
        }
        else if (strcmp(prop, "temperature") == 0 && ep->has_temperature) {
            lua_pushnumber(L, ep->temperature / 100.0);
            found = true;
        }
        else if (strcmp(prop, "humidity") == 0 && ep->has_humidity) {
            lua_pushnumber(L, ep->humidity / 100.0);
            found = true;
        }
        else if (strcmp(prop, "pressure") == 0 && ep->has_pressure) {
            lua_pushinteger(L, ep->pressure);
            found = true;
        }
        else if (strcmp(prop, "illuminance") == 0 && ep->has_illuminance) {
            lua_pushinteger(L, ep->illuminance);
            found = true;
        }
        else if (strcmp(prop, "occupancy") == 0 && ep->has_occupancy) {
            lua_pushboolean(L, ep->occupancy != 0);
            found = true;
        }
        else if (strcmp(prop, "level") == 0 && ep->has_level) {
            lua_pushinteger(L, ep->level);
            found = true;
        }
    }

    /* Device-level properties */
    if (!found) {
        if (strcmp(prop, "battery") == 0 && d->has_battery) {
            lua_pushinteger(L, d->battery_mv);
            found = true;
        }
        else if (strcmp(prop, "battery_pct") == 0 && d->has_battery) {
            int pct = (d->battery_mv - 2700) * 100 / 400;
            if (pct > 100) pct = 100;
            if (pct < 0) pct = 0;
            lua_pushinteger(L, pct);
            found = true;
        }
        else if (strcmp(prop, "device_temp") == 0) {
            lua_pushinteger(L, d->device_temp);
            found = true;
        }
    }

    device_unlock();

    if (!found) lua_pushnil(L);
    return 1;
}

/* ================================================================
 *  zigbee.devices() -> table of devices
 * ================================================================ */

static int l_zigbee_devices(lua_State *L)
{
    lua_newtable(L);
    int tbl_idx = 1;

    device_lock();
    zb_device_t *all = device_get_all();
    int remaining = device_count();

    for (int i = 0; i < CONFIG_GW_MAX_DEVICES && remaining > 0; i++) {
        zb_device_t *d = &all[i];
        if (!d->in_use) continue;
        remaining--;

        lua_createtable(L, 0, 5);

        char ieee_str[24];
        snprintf(ieee_str, sizeof(ieee_str), "%02x%02x%02x%02x%02x%02x%02x%02x",
                 d->ieee_addr[7], d->ieee_addr[6], d->ieee_addr[5], d->ieee_addr[4],
                 d->ieee_addr[3], d->ieee_addr[2], d->ieee_addr[1], d->ieee_addr[0]);
        lua_pushstring(L, ieee_str);
        lua_setfield(L, -2, "ieee");

        lua_pushstring(L, d->name[0] ? d->name : "");
        lua_setfield(L, -2, "name");

        lua_pushstring(L, d->manufacturer);
        lua_setfield(L, -2, "manufacturer");

        lua_pushstring(L, d->model);
        lua_setfield(L, -2, "model");

        lua_pushinteger(L, d->short_addr);
        lua_setfield(L, -2, "short_addr");

        lua_rawseti(L, -2, tbl_idx++);
    }
    device_unlock();

    return 1;
}

/* ================================================================
 *  zigbee.after(seconds, callback)
 * ================================================================ */

typedef struct {
    int script_idx;
    int func_ref;
    TimerHandle_t timer;
} after_ctx_t;

static void after_timer_cb(TimerHandle_t xTimer)
{
    after_ctx_t *ctx = (after_ctx_t *)pvTimerGetTimerID(xTimer);
    if (!ctx) return;

    /* Post event to the script's queue — Lua runs in the script task, not here */
    automation_post_timer_event(ctx->script_idx, ctx->func_ref);

    xTimerDelete(ctx->timer, 0);
    free(ctx);
}

static int l_zigbee_after(lua_State *L)
{
    int script_idx = get_script_idx(L);
    if (script_idx < 0) {
        return luaL_error(L, "zigbee.after() not available in test mode");
    }

    lua_Number seconds = luaL_checknumber(L, 1);
    luaL_checktype(L, 2, LUA_TFUNCTION);

    if (seconds <= 0 || seconds > 86400) {
        return luaL_error(L, "seconds must be 0..86400");
    }

    after_ctx_t *ctx = malloc(sizeof(after_ctx_t));
    if (!ctx) return luaL_error(L, "out of memory");

    ctx->script_idx = script_idx;
    lua_pushvalue(L, 2);
    ctx->func_ref = luaL_ref(L, LUA_REGISTRYINDEX);

    ctx->timer = xTimerCreate("lua_after", pdMS_TO_TICKS((int)(seconds * 1000)),
                              pdFALSE, ctx, after_timer_cb);
    if (!ctx->timer) {
        luaL_unref(L, LUA_REGISTRYINDEX, ctx->func_ref);
        free(ctx);
        return luaL_error(L, "timer create failed");
    }

    xTimerStart(ctx->timer, 0);
    return 0;
}

/* ================================================================
 *  zigbee.log(message)
 * ================================================================ */

/* Defined in automation.c */
extern void automation_test_log_append(const char *msg);

static int l_zigbee_log(lua_State *L)
{
    const char *msg = luaL_checkstring(L, 1);
    ESP_LOGI("lua", "%s", msg);
    automation_test_log_append(msg);
    return 0;
}

/* ================================================================
 *  zigbee module registration
 * ================================================================ */

static const luaL_Reg zigbee_funcs[] = {
    {"on",           l_zigbee_on},
    {"turn_on",      l_zigbee_turn_on},
    {"turn_off",     l_zigbee_turn_off},
    {"toggle",       l_zigbee_toggle},
    {"get_property", l_zigbee_get_property},
    {"devices",      l_zigbee_devices},
    {"after",        l_zigbee_after},
    {"log",          l_zigbee_log},
    {NULL, NULL}
};

void lua_api_register_zigbee(lua_State *L, int script_idx)
{
    /* Store script index in registry */
    lua_pushinteger(L, script_idx);
    lua_setfield(L, LUA_REGISTRYINDEX, SCRIPT_IDX_KEY);

    luaL_newlib(L, zigbee_funcs);
    lua_setglobal(L, "zigbee");
}

/* ================================================================
 *  system.datetime(component)
 * ================================================================ */

static int l_system_datetime(lua_State *L)
{
    const char *comp = luaL_checkstring(L, 1);

    time_t now;
    time(&now);
    struct tm tm;
    localtime_r(&now, &tm);

    if (strcmp(comp, "hour") == 0)          lua_pushinteger(L, tm.tm_hour);
    else if (strcmp(comp, "minute") == 0)   lua_pushinteger(L, tm.tm_min);
    else if (strcmp(comp, "second") == 0)   lua_pushinteger(L, tm.tm_sec);
    else if (strcmp(comp, "weekday") == 0)  lua_pushinteger(L, tm.tm_wday);
    else if (strcmp(comp, "day") == 0)      lua_pushinteger(L, tm.tm_mday);
    else if (strcmp(comp, "month") == 0)    lua_pushinteger(L, tm.tm_mon + 1);
    else if (strcmp(comp, "year") == 0)     lua_pushinteger(L, tm.tm_year + 1900);
    else if (strcmp(comp, "timestamp") == 0) lua_pushinteger(L, (lua_Integer)now);
    else if (strcmp(comp, "time_str") == 0) {
        char buf[16];
        snprintf(buf, sizeof(buf), "%02d:%02d:%02d", tm.tm_hour, tm.tm_min, tm.tm_sec);
        lua_pushstring(L, buf);
    }
    else if (strcmp(comp, "date_str") == 0) {
        char buf[32];
        snprintf(buf, sizeof(buf), "%04d-%02d-%02d", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);
        lua_pushstring(L, buf);
    }
    else lua_pushnil(L);

    return 1;
}

/* ================================================================
 *  system.time_between(from_hour, to_hour)
 * ================================================================ */

static int l_system_time_between(lua_State *L)
{
    int from_h = (int)luaL_checkinteger(L, 1);
    int to_h   = (int)luaL_checkinteger(L, 2);

    time_t now;
    time(&now);
    struct tm tm;
    localtime_r(&now, &tm);
    int h = tm.tm_hour;

    bool result;
    if (from_h <= to_h) {
        result = (h >= from_h && h < to_h);
    } else {
        /* Wraps midnight: e.g. 22..6 means 22,23,0,1,2,3,4,5 */
        result = (h >= from_h || h < to_h);
    }

    lua_pushboolean(L, result);
    return 1;
}

/* ================================================================
 *  system.log(level, message)
 * ================================================================ */

static int l_system_log(lua_State *L)
{
    const char *level = luaL_checkstring(L, 1);
    const char *msg   = luaL_checkstring(L, 2);

    if (strcmp(level, "error") == 0)       ESP_LOGE("lua", "%s", msg);
    else if (strcmp(level, "warn") == 0)   ESP_LOGW("lua", "%s", msg);
    else if (strcmp(level, "debug") == 0)  ESP_LOGD("lua", "%s", msg);
    else                                   ESP_LOGI("lua", "%s", msg);

    automation_test_log_append(msg);
    return 0;
}

/* ================================================================
 *  system module registration
 * ================================================================ */

static const luaL_Reg system_funcs[] = {
    {"datetime",     l_system_datetime},
    {"time_between", l_system_time_between},
    {"log",          l_system_log},
    {NULL, NULL}
};

void lua_api_register_system(lua_State *L)
{
    luaL_newlib(L, system_funcs);
    lua_setglobal(L, "system");
}
