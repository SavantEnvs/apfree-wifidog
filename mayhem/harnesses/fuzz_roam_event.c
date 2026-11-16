/* Feeds one JSON message to the roaming-sync event dispatcher (roam_sync_dispatch_event in
 * src/roam_sync.c). The WebSocket text-frame handler (process_ws_msg) and the MQTT request handler
 * (process_mqtt_request) hand it every control message that carries an "event" key, verbatim, as a
 * NUL-terminated string. AUTH_ADD / AUTH_DEL / AUTH_UPDATE / ROAM_SNAPSHOT_SYNC / CONFIG_UPDATE
 * update the roaming cache, the client list and the venue id; all of it is cleared after each input. */
#include "../../src/roam_sync.c"
#include "../../src/conf.h"

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc; (void)argv;
	config_init();
	debugconf.debuglevel = 0;
	debugconf.log_stderr = 0;
	roam_sync_init();
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char *msg = malloc(size + 1);
	if (!msg)
		return 0;
	memcpy(msg, data, size);
	msg[size] = '\0';
	roam_sync_dispatch_event(msg);
	free(msg);

	roam_cache_clear();
	memset(g_roam_table.venue_id, 0, sizeof(g_roam_table.venue_id));
	return 0;
}
