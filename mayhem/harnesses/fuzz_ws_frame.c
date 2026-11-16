/* Feeds one received WebSocket frame to the cloud-control channel's frame parser (ws_receive in
 * src/ws_thread.c), the way ws_read_cb does after the HTTP upgrade. Text frames go on to
 * process_ws_msg (JSON parse, roaming-event dispatch, API routing); PING/CLOSE/unknown opcodes
 * write replies to a real libevent bufferevent pair whose output is drained after each input. */
#include "../../src/ws_thread.c"

static struct event_base *g_base;
static struct bufferevent *g_pair[2];

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc; (void)argv;
	config_init();
	debugconf.debuglevel = 0;
	debugconf.log_stderr = 0;
	roam_sync_init();
	g_base = event_base_new();
	if (!g_base || bufferevent_pair_new(g_base, 0, g_pair) != 0)
		abort();
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	/* ws_read_cb collects at most sizeof(data) - 1 = 1023 bytes before calling ws_receive */
	if (size >= 1024)
		return -1;

	unsigned char *buf = malloc(size ? size : 1);
	if (!buf)
		return 0;
	memcpy(buf, data, size);
	ws_receive(g_pair[0], buf, size);
	free(buf);

	struct evbuffer *out = bufferevent_get_output(g_pair[0]);
	evbuffer_drain(out, evbuffer_get_length(out));
	roam_cache_clear();
	roam_sync_set_venue_id("");
	return 0;
}
