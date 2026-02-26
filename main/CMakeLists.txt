idf_component_register(
    SRCS
        "main.c"
        "wifi.c"
        "zigbee.c"
        "device_list.c"
        "device_defs.c"
        "web_server.c"
        "ws_server.c"
    INCLUDE_DIRS "."
    EMBED_TXTFILES "web/index.html"
)

idf_build_get_property(python PYTHON)

if(CONFIG_ZIGBEE_GW_AUTO_UPDATE_RCP)
    set(RCP_BUILD_DIR "${IDF_PATH}/examples/openthread/ot_rcp/build")
    set(RCP_OTA_SCRIPT "${CMAKE_CURRENT_SOURCE_DIR}/../create_ota_image.py")

    if(EXISTS ${RCP_OTA_SCRIPT} AND EXISTS ${RCP_BUILD_DIR})
        add_custom_target(rcp_image_generation ALL
            COMMAND ${python} ${RCP_OTA_SCRIPT}
                --rcp-build-dir ${RCP_BUILD_DIR}
                --target-file ${CMAKE_CURRENT_BINARY_DIR}/spiffs_image/ot_rcp_0/rcp_image
        )
        spiffs_create_partition_image(rcp_fw ${CMAKE_CURRENT_BINARY_DIR}/spiffs_image
            FLASH_IN_PROJECT DEPENDS rcp_image_generation)
        message(STATUS ">>> RCP auto-update ENABLED (image from ${RCP_BUILD_DIR})")
    else()
        message(STATUS ">>> RCP auto-update configured but ot_rcp not built or create_ota_image.py missing")
        message(STATUS "    Build ot_rcp first: cd $IDF_PATH/examples/openthread/ot_rcp && idf.py set-target esp32h2 && idf.py build")
    endif()
endif()
