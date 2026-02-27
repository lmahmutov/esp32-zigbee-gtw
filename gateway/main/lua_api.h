#pragma once

#include "lua.h"

/* Register zigbee.* module into Lua state.
   script_idx: index into automation script array (-1 = test mode) */
void lua_api_register_zigbee(lua_State *L, int script_idx);

/* Register system.* module into Lua state */
void lua_api_register_system(lua_State *L);
