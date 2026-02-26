#!/bin/bash
# Deploy firmware to VDS (both OTA location and web flasher)
set -e

VDS="root@77.91.79.32"
BUILD="/home/lenar/esp32/esp32-gateway/build"

echo "=== Deploying firmware to VDS ==="

# OTA location (legacy)
scp "$BUILD/zigbee-gateway.bin" "$VDS:/root/esp-gateway/"

# Web flasher firmware
scp "$BUILD/bootloader/bootloader.bin" \
    "$BUILD/partition_table/partition-table.bin" \
    "$BUILD/ota_data_initial.bin" \
    "$BUILD/zigbee-gateway.bin" \
    "$BUILD/rcp_fw.bin" \
    "$VDS:/root/esp-flasher/firmware/"

echo "=== Done ==="
echo "OTA:     http://77.91.79.32/esp-gateway/zigbee-gateway.bin"
echo "Flasher: http://77.91.79.32:8090"
