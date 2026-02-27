#include "dns_server.h"

#include <string.h>
#include "esp_log.h"
#include "esp_netif.h"
#include "lwip/sockets.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "dns";

#define DNS_PORT 53

typedef struct __attribute__((packed)) {
    uint16_t id;
    uint16_t flags;
    uint16_t qd_count;
    uint16_t an_count;
    uint16_t ns_count;
    uint16_t ar_count;
} dns_header_t;

typedef struct __attribute__((packed)) {
    uint16_t ptr_offset;
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t addr_len;
    uint32_t ip_addr;
} dns_answer_t;

static TaskHandle_t s_task;
static volatile bool s_running;

static uint32_t get_ap_ip(void)
{
    esp_netif_ip_info_t ip_info;
    esp_netif_t *netif = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
    if (netif && esp_netif_get_ip_info(netif, &ip_info) == ESP_OK) {
        return ip_info.ip.addr;
    }
    return htonl(0xC0A80401); /* 192.168.4.1 fallback */
}

static void dns_task(void *arg)
{
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        ESP_LOGE(TAG, "socket: errno %d", errno);
        goto done;
    }

    struct sockaddr_in saddr = {
        .sin_family = AF_INET,
        .sin_port = htons(DNS_PORT),
        .sin_addr.s_addr = INADDR_ANY,
    };
    if (bind(sock, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
        ESP_LOGE(TAG, "bind: errno %d", errno);
        close(sock);
        goto done;
    }

    /* Non-blocking so we can check s_running periodically */
    struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    ESP_LOGI(TAG, "Captive portal DNS started");

    char rx[256], reply[256];

    while (s_running) {
        struct sockaddr_in client;
        socklen_t clen = sizeof(client);
        int n = recvfrom(sock, rx, sizeof(rx), 0, (struct sockaddr *)&client, &clen);
        if (n < (int)sizeof(dns_header_t) + 5) continue;

        dns_header_t *hdr = (dns_header_t *)rx;
        /* Only handle standard queries (QR=0, OPCODE=0) */
        if ((ntohs(hdr->flags) & 0xF800) != 0) continue;

        /* Copy query to reply buffer */
        memcpy(reply, rx, n);
        dns_header_t *resp = (dns_header_t *)reply;
        resp->flags = htons(0x8580); /* QR=1, AA=1, RD=1, RA=1 */
        uint16_t qd_count = ntohs(resp->qd_count);
        resp->an_count = resp->qd_count;
        resp->ns_count = 0;
        resp->ar_count = 0;

        /* Sanity-check question count to prevent buffer over-read */
        if (qd_count > 4) continue;

        /* Walk past question section to find where to append answers */
        int off = sizeof(dns_header_t);
        int first_qname_off = off;
        for (int q = 0; q < qd_count && off < n; q++) {
            /* Skip QNAME labels */
            while (off < n) {
                if (rx[off] == 0) { off++; break; }
                if ((rx[off] & 0xC0) == 0xC0) { off += 2; break; }
                off += (uint8_t)rx[off] + 1;
            }
            if (off + 4 <= n) off += 4; /* QTYPE(2) + QCLASS(2) */
            else { off = n; break; }
        }
        if (off > n) off = n;

        /* Append one answer per question — all point to AP IP */
        uint32_t ap_ip = get_ap_ip();
        int resp_len = off;
        for (int q = 0; q < qd_count && resp_len + (int)sizeof(dns_answer_t) <= (int)sizeof(reply); q++) {
            dns_answer_t *ans = (dns_answer_t *)(reply + resp_len);
            ans->ptr_offset = htons(0xC000 | first_qname_off);
            ans->type = htons(1);      /* A */
            ans->class = htons(1);     /* IN */
            ans->ttl = htonl(60);
            ans->addr_len = htons(4);
            ans->ip_addr = ap_ip;
            resp_len += sizeof(dns_answer_t);
        }

        if (resp_len > (int)sizeof(reply)) resp_len = (int)sizeof(reply);
        sendto(sock, reply, resp_len, 0, (struct sockaddr *)&client, clen);
    }

    close(sock);
done:
    s_task = NULL;
    vTaskDelete(NULL);
}

void dns_server_start(void)
{
    if (s_task) return;
    s_running = true;
    xTaskCreate(dns_task, "dns", 3072, NULL, 3, &s_task);
}

void dns_server_stop(void)
{
    if (!s_task) return;
    s_running = false;
    /* Task will exit on next recvfrom timeout (2s) */
}
