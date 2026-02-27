#pragma once

/* Captive portal DNS server — resolves ALL A queries to the AP IP (192.168.4.1).
   Start when SoftAP is active so phones detect the captive portal. */

void dns_server_start(void);
void dns_server_stop(void);
