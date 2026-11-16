/* Known-answer tests for the trusted-domain / MAC / popular-server list parsers (conf.c) and the
 * portal DNS response parser (dns_snoop.c). Built with the project's normal flags by build.sh and
 * run by test.sh, which checks the "SELFTEST" summary line this program prints. */
#include "../src/conf.c"
#include "../src/dns_snoop.c"

static int g_passed, g_failed;
static int g_fw_calls;
static char g_fw_last[INET6_ADDRSTRLEN];

void fw_add_wildcard_resolved_ip(const char *ip)
{
	g_fw_calls++;
	snprintf(g_fw_last, sizeof(g_fw_last), "%s", ip);
}

#define CHECK(cond) do { \
	if (cond) g_passed++; \
	else { g_failed++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } \
} while (0)

static t_domain_trusted *find_domain(t_domain_trusted *list, const char *name)
{
	for (; list; list = list->next)
		if (strcasecmp(list->domain, name) == 0)
			return list;
	return NULL;
}

static int domain_has_ip(t_domain_trusted *d, const char *ip)
{
	t_ip_trusted *i;
	for (i = d ? d->ips_trusted : NULL; i; i = i->next)
		if (strcmp(i->ip, ip) == 0)
			return 1;
	return 0;
}

static int list_len(t_domain_trusted *list)
{
	int n = 0;
	for (; list; list = list->next)
		n++;
	return n;
}

static void reset_state(void)
{
	free_domain_trusted_list(config.domains_trusted);
	config.domains_trusted = NULL;
	free_domain_trusted_list(config.inner_domains_trusted);
	config.inner_domains_trusted = NULL;
	free_domain_trusted_list(config.wildcard_domains_trusted);
	config.wildcard_domains_trusted = NULL;
	free_popular_servers_list(config.popular_servers);
	config.popular_servers = NULL;
	clear_trusted_mac_list();
	clear_untrusted_mac_list();
	g_fw_calls = 0;
	g_fw_last[0] = '\0';
}

static void test_domain_lists(void)
{
	reset_state();
	parse_user_trusted_domain_string("Example.com, test.org ,,a.b.c");
	CHECK(list_len(config.domains_trusted) == 3);
	CHECK(find_domain(config.domains_trusted, "example.com") != NULL);
	CHECK(find_domain(config.domains_trusted, "test.org") != NULL);
	CHECK(find_domain(config.domains_trusted, "a.b.c") != NULL);
	CHECK(find_domain(config.domains_trusted, "missing.net") == NULL);

	parse_user_trusted_domain_string("example.com");
	CHECK(list_len(config.domains_trusted) == 3);

	parse_del_trusted_domain_string("test.org");
	CHECK(list_len(config.domains_trusted) == 2);
	CHECK(find_domain(config.domains_trusted, "test.org") == NULL);

	add_domain_ip_pair("example.com:10.1.2.3", USER_TRUSTED_DOMAIN);
	CHECK(domain_has_ip(find_domain(config.domains_trusted, "example.com"), "10.1.2.3"));
	add_domain_ip_pair("inner.lan:192.168.1.1", INNER_TRUSTED_DOMAIN);
	CHECK(domain_has_ip(find_domain(config.inner_domains_trusted, "inner.lan"), "192.168.1.1"));
	add_domain_ip_pair("bad.lan:1.2", INNER_TRUSTED_DOMAIN);
	CHECK(find_domain(config.inner_domains_trusted, "bad.lan") == NULL);

	parse_trusted_wildcard_domain_string("*.example.com,.test");
	CHECK(list_len(config.wildcard_domains_trusted) == 2);
	parse_del_trusted_wildcard_domain_string("*.example.com");
	CHECK(list_len(config.wildcard_domains_trusted) == 1);
	CHECK(find_domain(config.wildcard_domains_trusted, ".test") != NULL);
	reset_state();
}

static void test_wildcards(void)
{
	reset_state();
	parse_trusted_wildcard_domain_string("*.example.com,.test,exact.org");
	CHECK(add_wildcard_resolved_ip("www.example.com", "1.1.1.1") == 1);
	CHECK(add_wildcard_resolved_ip("www.example.com", "1.1.1.1") == 0);
	CHECK(add_wildcard_resolved_ip("deep.sub.example.com", "2.2.2.2") == 1);
	CHECK(add_wildcard_resolved_ip("example.net", "3.3.3.3") == 0);
	CHECK(add_wildcard_resolved_ip("a.test", "4.4.4.4") == 1);
	CHECK(add_wildcard_resolved_ip("test", "4.4.4.5") == 1);
	CHECK(add_wildcard_resolved_ip("exact.org", "5.5.5.5") == 1);
	CHECK(add_wildcard_resolved_ip("sub.exact.org", "5.5.5.6") == 0);
	CHECK(domain_has_ip(find_domain(config.wildcard_domains_trusted, "*.example.com"), "1.1.1.1"));
	CHECK(domain_has_ip(find_domain(config.wildcard_domains_trusted, "*.example.com"), "2.2.2.2"));
	CHECK(!domain_has_ip(find_domain(config.wildcard_domains_trusted, ".test"), "3.3.3.3"));
	reset_state();
}

static void test_macs(void)
{
	reset_state();
	parse_trusted_mac_list("00:11:22:33:44:55,aa:bb:cc:dd:ee:ff,nonsense");
	CHECK(is_trusted_mac("00:11:22:33:44:55"));
	CHECK(is_trusted_mac("aa:bb:cc:dd:ee:ff"));
	CHECK(!is_trusted_mac("nonsense"));
	CHECK(!is_trusted_mac("00:11:22:33:44:56"));
	parse_del_trusted_mac_list("00:11:22:33:44:55");
	CHECK(!is_trusted_mac("00:11:22:33:44:55"));
	CHECK(is_trusted_mac("aa:bb:cc:dd:ee:ff"));
	clear_trusted_mac_list();
	CHECK(!is_trusted_mac("aa:bb:cc:dd:ee:ff"));

	parse_untrusted_mac_list("01:02:03:04:05:06");
	CHECK(config.mac_blacklist != NULL);
	CHECK(strcmp(config.mac_blacklist->mac, "01:02:03:04:05:06") == 0);
	parse_del_untrusted_mac_list("01:02:03:04:05:06");
	CHECK(config.mac_blacklist == NULL);
	reset_state();
}

static void test_popular_servers(void)
{
	t_popular_server *p;
	int n = 0;

	reset_state();
	parse_popular_servers("www.google.com, www.apple.com  extra,,www.qq.com");
	for (p = config.popular_servers; p; p = p->next)
		n++;
	CHECK(n == 3);
	CHECK(strcmp(config.popular_servers->hostname, "www.qq.com") == 0);
	CHECK(strcmp(config.popular_servers->next->hostname, "www.apple.com") == 0);
	reset_state();
}

static int put_name(unsigned char *buf, int pos, const char *name)
{
	const char *p = name;
	while (*p) {
		const char *dot = strchr(p, '.');
		int len = dot ? (int)(dot - p) : (int)strlen(p);
		buf[pos++] = (unsigned char)len;
		memcpy(buf + pos, p, len);
		pos += len;
		p += len + (dot ? 1 : 0);
	}
	buf[pos++] = 0;
	return pos;
}

static int build_response(unsigned char *buf, const char *qname, uint16_t flags,
			  const unsigned char *rdata, uint16_t type, uint16_t rdlen)
{
	int pos = 0;
	memset(buf, 0, 512);
	buf[0] = 0x12; buf[1] = 0x34;
	buf[2] = flags >> 8; buf[3] = flags & 0xff;
	buf[5] = 1;
	buf[7] = 1;
	pos = put_name(buf, 12, qname);
	buf[pos++] = 0; buf[pos++] = type;
	buf[pos++] = 0; buf[pos++] = 1;
	buf[pos++] = 0xC0; buf[pos++] = 0x0C;
	buf[pos++] = type >> 8; buf[pos++] = type & 0xff;
	buf[pos++] = 0; buf[pos++] = 1;
	pos += 4;
	buf[pos++] = rdlen >> 8; buf[pos++] = rdlen & 0xff;
	memcpy(buf + pos, rdata, rdlen);
	return pos + rdlen;
}

static void test_dns(void)
{
	unsigned char pkt[512];
	static const unsigned char v4[4] = { 93, 184, 216, 34 };
	static const unsigned char v6[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
	char name[64];
	int len;

	reset_state();
	parse_trusted_wildcard_domain_string("*.example.com,.test");

	len = build_response(pkt, "WWW.Example.com", 0x8180, v4, 1, 4);
	handle_dns_payload(pkt, len);
	CHECK(g_fw_calls == 1);
	CHECK(strcmp(g_fw_last, "93.184.216.34") == 0);
	CHECK(domain_has_ip(find_domain(config.wildcard_domains_trusted, "*.example.com"), "93.184.216.34"));

	handle_dns_payload(pkt, len);
	CHECK(g_fw_calls == 1);

	len = build_response(pkt, "host.test", 0x8180, v6, 28, 16);
	handle_dns_payload(pkt, len);
	CHECK(g_fw_calls == 2);
	CHECK(strcmp(g_fw_last, "2001:db8::1") == 0);

	len = build_response(pkt, "www.other.org", 0x8180, v4, 1, 4);
	handle_dns_payload(pkt, len);
	CHECK(g_fw_calls == 2);

	len = build_response(pkt, "q.example.com", 0x0100, v4, 1, 4);
	handle_dns_payload(pkt, len);
	CHECK(g_fw_calls == 2);

	len = build_response(pkt, "r.example.com", 0x8180, v4, 1, 4);
	handle_dns_payload(pkt, len - 2);
	CHECK(g_fw_calls == 2);

	len = build_response(pkt, "s.example.com", 0x8180, v4, 1, 4);
	pkt[7] = 0;
	handle_dns_payload(pkt, len);
	CHECK(g_fw_calls == 2);

	len = build_response(pkt, "Mixed.Example.COM", 0x8180, v4, 1, 4);
	CHECK(parse_dns_name(pkt, len, 12, name, sizeof(name)) == 12 + 19);
	CHECK(strcmp(name, "mixed.example.com") == 0);
	CHECK(parse_dns_name(pkt, 5, 12, name, sizeof(name)) == -1);
	pkt[12] = 0xC0; pkt[13] = 0x20;
	CHECK(parse_dns_name(pkt, len, 12, name, sizeof(name)) == -1);

	{
		static const unsigned char v4b[4] = { 10, 20, 30, 40 };
		struct raw_dns_data ev;
		memset(&ev, 0, sizeof(ev));
		len = build_response(pkt, "evt.example.com", 0x8180, v4b, 1, 4);
		memcpy(ev.dns_payload, pkt, len);
		ev.pkt_len = len;
		g_fw_calls = 0;
		handle_portal_dns_event(NULL, &ev, sizeof(ev));
		CHECK(g_fw_calls == 1);
		CHECK(strcmp(g_fw_last, "10.20.30.40") == 0);
		ev.dns_payload[len - 1] = 41;
		handle_portal_dns_event(NULL, &ev, sizeof(ev) - 1);
		CHECK(g_fw_calls == 1);
	}
	reset_state();
}

int main(void)
{
	config_init();
	debugconf.debuglevel = 0;
	debugconf.log_stderr = 0;

	test_domain_lists();
	test_wildcards();
	test_macs();
	test_popular_servers();
	test_dns();

	printf("SELFTEST passed=%d failed=%d\n", g_passed, g_failed);
	return g_failed ? 1 : 0;
}
