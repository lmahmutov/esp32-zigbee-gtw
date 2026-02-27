idf_component_register(
    SRCS
        "main.c"
        "wifi.c"
        "zigbee.c"
        "device_list.c"
        "device_defs.c"
        "web_server.c"
        "ws_server.c"
        "dns_server.c"
        "automation.c"
        "lua_api.c"
    INCLUDE_DIRS "."
    EMBED_TXTFILES "web/index.html"
    EMBED_FILES "web/blockly.js.gz"
)
