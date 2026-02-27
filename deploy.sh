#!/bin/bash
# Deploy firmware to VDS (both OTA location and web flasher)
set -e

VDS="root@77.91.79.32"
GW_BUILD="/home/lenar/esp32/esp32-gateway/build"
NCP_BUILD="/home/lenar/esp32/esp32-ncp/build"

# Extract version from main.c
GW_VER=$(grep -oP '"\K[0-9]+\.[0-9]+\.[0-9]+' /home/lenar/esp32/esp32-gateway/main/main.c | head -1)
GW_DATE=$(date -r "$GW_BUILD/zigbee-gateway.bin" '+%Y-%m-%d %H:%M')
NCP_DATE=""
NCP_VER="$GW_VER"

echo "=== Deploying firmware to VDS ==="
echo "Gateway: v${GW_VER} (${GW_DATE})"

# OTA location (legacy — fixed name for OTA update)
scp "$GW_BUILD/zigbee-gateway.bin" "$VDS:/root/esp-gateway/"

# Web flasher — ESP32-S3 gateway firmware (versioned names)
ssh "$VDS" "rm -f /root/esp-flasher/firmware/s3/zigbee-gateway-*.bin"
scp "$GW_BUILD/bootloader/bootloader.bin" \
    "$GW_BUILD/partition_table/partition-table.bin" \
    "$GW_BUILD/ota_data_initial.bin" \
    "$VDS:/root/esp-flasher/firmware/s3/"
scp "$GW_BUILD/zigbee-gateway.bin" \
    "$VDS:/root/esp-flasher/firmware/s3/zigbee-gateway-${GW_VER}.bin"
ssh "$VDS" "cd /root/esp-flasher/firmware/s3 && ln -sf zigbee-gateway-${GW_VER}.bin zigbee-gateway.bin"
# SPIFFS image with device definitions
scp "$GW_BUILD/storage.bin" \
    "$VDS:/root/esp-flasher/firmware/s3/"

# Web flasher — ESP32-H2 NCP firmware (versioned names)
if [ -d "$NCP_BUILD" ]; then
    NCP_DATE=$(date -r "$NCP_BUILD/esp_zigbee_ncp.bin" '+%Y-%m-%d %H:%M')
    ssh "$VDS" "rm -f /root/esp-flasher/firmware/h2/esp_zigbee_ncp-*.bin"
    scp "$NCP_BUILD/bootloader/bootloader.bin" \
        "$NCP_BUILD/partition_table/partition-table.bin" \
        "$NCP_BUILD/ota_data_initial.bin" \
        "$VDS:/root/esp-flasher/firmware/h2/"
    scp "$NCP_BUILD/esp_zigbee_ncp.bin" \
        "$VDS:/root/esp-flasher/firmware/h2/esp_zigbee_ncp-${NCP_VER}.bin"
    ssh "$VDS" "cd /root/esp-flasher/firmware/h2 && ln -sf esp_zigbee_ncp-${NCP_VER}.bin esp_zigbee_ncp.bin"
    echo "NCP firmware deployed (${NCP_DATE})"
else
    echo "WARNING: NCP build not found at $NCP_BUILD — skipping H2 firmware"
fi

# Generate manifest.json
GW_SIZE=$(stat -c%s "$GW_BUILD/zigbee-gateway.bin")
NCP_SIZE=$([ -f "$NCP_BUILD/esp_zigbee_ncp.bin" ] && stat -c%s "$NCP_BUILD/esp_zigbee_ncp.bin" || echo 0)
ssh "$VDS" "cat > /root/esp-flasher/firmware/manifest.json" <<EOF
{
  "s3": {
    "version": "${GW_VER}",
    "date": "${GW_DATE}",
    "size": ${GW_SIZE},
    "app": "zigbee-gateway-${GW_VER}.bin"
  },
  "h2": {
    "version": "${NCP_VER}",
    "date": "${NCP_DATE}",
    "size": ${NCP_SIZE},
    "app": "esp_zigbee_ncp-${NCP_VER}.bin"
  }
}
EOF

echo "=== Done ==="
echo "OTA:     http://77.91.79.32/esp-gateway/zigbee-gateway.bin"
echo "Flasher: http://77.91.79.32:8090"
