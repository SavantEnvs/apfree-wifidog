/* Link-time stand-ins for daemon pieces (netfilter, DNS resolver thread, roaming cache) that the
 * harnesses do not exercise; each is a no-op with the daemon's own signature. The roaming ones are weak:
 * fuzz_ws_frame and fuzz_roam_event link the real src/roam_sync.c. */
#include <stdlib.h>
#include "../src/conf.h"
#include "../src/firewall.h"
#include "../src/wd_util.h"
#include "../src/roam_sync.h"

char *program_argv0 = NULL;

__attribute__((weak)) void fw_add_wildcard_resolved_ip(const char *ip) { (void)ip; }
void evdns_parse_trusted_domain_2_ip(trusted_domain_t which) { (void)which; }
__attribute__((weak)) void roam_sync_set_venue_id(const char *venue_id) { (void)venue_id; }
__attribute__((weak)) void roam_cache_purge_expired(void) {}
bool is_openwrt_platform(void) { return false; }
