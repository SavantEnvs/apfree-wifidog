/* Link-time stand-ins for the daemon pieces behind the cloud-control channel that fuzz_ws_frame and
 * fuzz_roam_event do not exercise. Each keeps the daemon's own signature.
 *
 * api_get_routes: the real table (src/api_routes.c) routes to the shell, firmware-upgrade, firewall,
 * Wi-Fi and VPN handlers, which run commands and change the host; the harness routes no op, so
 * api_dispatch_request (real, src/api_handlers.c) takes its "Unknown operation" path and the real
 * error reply is framed by ws_send into the harness's bufferevent. */
#include <stddef.h>
#include "../src/common.h"
#include "../src/api_handlers.h"
#include "../src/firewall.h"
#include "../src/long_conn.h"
#include "../src/mqtt_thread.h"
#include "../src/wd_util.h"

static const api_route_entry_t no_routes[] = { {NULL, NULL} };
const api_route_entry_t *api_get_routes(void) { return no_routes; }

/* netfilter, auth-server liveness, MQTT broker and long-connection counters: no network or firewall */
int fw_deny(t_client *client) { (void)client; return 0; }
void mark_auth_online(void) {}
void mark_auth_offline(void) {}
int mqtt_is_connected(void) { return 0; }
void mqtt_subscribe_venue_topic(const char *venue_id) { (void)venue_id; }
void long_conn_publish_counters(void) {}
void long_conn_handle_server_response(json_object *jobj) { (void)jobj; }
json_object *build_gateway_report_message(const char *op) { (void)op; return NULL; }
