/*
 *  (C) Copyright 2012
 *			Wiesław Ochmiński <wiechu at wiechu dot com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License Version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "ekg2.h"

#include <arpa/inet.h>
#include <string.h>

#define EKG_CONNECTION_ERROR ekg_connection_error_quark()

typedef struct connection_starter_t connection_starter_t;

struct connection_starter_t {
	connection_data_t	*cd;

	char	**servers;
	/* SRV */
	char	*domain;
	char	*service;

	/* data for connect_loop() */
	char	**srvhosts;	/* jobs for resolver */
	char	**ips;		/* preferred IPs to connect */
	char	**ips2;		/* unpreferred IPs to connect */

	/* data provided by user */
	GSocketFamily	prefer_family;		/* preferred address family */
	int	default_port;			/* default port of a protocol */
	int	port;
	ekg2_connect_handler_t connect_handler;
	ekg2_connect_failure_t connect_failure_handler;
	/* private */
	GIOChannel *channel;
	int pipe_watch_id;
	int pipe_in;
	int pipe_out;
};

struct connection_data_t {
	GError	*error;
	gchar	*sess_id;
	/* private */
	/* connection */
	int		watch_id;
	gboolean	tls;
	GSocket		*socket;
	GIOStream	*conn;
	GIOChannel	*channel;
	GInputStream	*in_stream;
	GOutputStream	*out_stream;
	/* buffers */
	GString		*in_buf;
	gboolean	use_out_buf;
	GString		*out_buf;
	/* handlers */
	ekg2_connection_input_callback_t
			input_callback;
	ekg2_connection_failure_t
			failure_callback;
	ekg2_connection_disconnect_t
			disconnect_handler;
	/* private */
	connection_starter_t *cs;
};

typedef enum {
	EKG2_AR_SRV,
	EKG2_AR_RESOLVER,
	EKG2_AR_ERROR,
} aresolv_t;

GQuark ekg_connection_error_quark() {
	return g_quark_from_static_string("ekg-connection-error-quark");
}

connection_data_t *ekg2_connection_new(session_t *session, guint16 defport) {
	int fd[2];
	connection_data_t *cd;
	connection_starter_t *cs;

	cd = g_new0(struct connection_data_t, 1);

	cd->in_buf = g_string_new("");
	cd->out_buf = g_string_new("");

	cd->sess_id = g_strdup(session_uid_get(session));

	cs = g_new0(struct connection_starter_t, 1);
	cs->port = defport;
	cs->default_port = defport;
	cs->prefer_family = G_SOCKET_FAMILY_IPV4;
	if (pipe(fd) != -1) {
		cs->pipe_in = fd[0];
		cs->pipe_out = fd[1];
	}

	cd->cs	= cs;

	return cd;
}

static void connect_starter_free(connection_data_t *cd) {
	connection_starter_t *cs = cd->cs;

	g_return_if_fail(cd != NULL);
	if (!cs)
		return;

	g_free(cs->domain);
	g_free(cs->service);
	g_strfreev(cs->servers);
	g_strfreev(cs->srvhosts);
	g_strfreev(cs->ips);
	g_strfreev(cs->ips2);

	g_source_remove(cs->pipe_watch_id);

	close(cs->pipe_out);
	close(cs->pipe_in);

	g_free(cs);
	cd->cs = NULL;
}

void ekg2_connection_close(connection_data_t **acd) {
	connection_data_t *cd = *acd;
	session_t *s;
	GError *error = NULL;

	g_return_if_fail(cd != NULL);

	connect_starter_free(cd);

	s = session_find(cd->sess_id);

	debug_function("ekg2_connection_close(%s)\n", session_uid_get(s));

	g_source_remove(cd->watch_id);

	g_string_free(cd->in_buf, TRUE);
	g_string_free(cd->out_buf, TRUE);

	if (cd->conn) {
		if (!g_io_stream_close(cd->conn, NULL, &error))
			debug_error("Error closing connection: %s\n", error->message);
		g_object_unref(cd->conn);
	} else {
		if (cd->socket && !g_socket_close(cd->socket, &error))
			debug_error("Error closing master socket: %s\n", error->message);
	}

	if (cd->socket) g_object_unref(cd->socket);

	if (cd->error) g_error_free(cd->error);
	if (error) g_error_free(error);

	g_free(cd->sess_id);

	g_free(cd);

	*acd = NULL;
}

void ekg2_connection_set_servers(connection_data_t *cd, const gchar *servers) {
	g_return_if_fail(cd != NULL);
	g_return_if_fail(cd->cs != NULL);

	g_strfreev(cd->cs->servers);
	cd->cs->servers = g_strsplit(servers, ",", 0);
}

void ekg2_connection_set_srv(connection_data_t *cd, gchar *service, gchar *domain) {
	debug_function("ekg2_connection_set_srv(%s,%s)\n",service,domain);	// XXX-temp

	g_free(cd->cs->domain);
	cd->cs->domain = g_strdup(domain);
	g_free(cd->cs->service);
	cd->cs->service = g_strdup(service);
}

void ekg2_connection_set_tls(connection_data_t *cd, gboolean use_tls) {
	cd->tls = use_tls;
}

gboolean ekg2_connection_is_secure(connection_data_t *cd) {
	// XXX
	return cd->tls;
}

GError *ekg2_connection_get_error(connection_data_t *cd) {
	// XXX
	return cd->error;
}

void ekg2_connection_write_use_buffer(connection_data_t *cd, gboolean use_buffer) {
	// XXX
	cd->use_out_buf = use_buffer;
}

session_t *ekg2_connection_get_session(connection_data_t *cd) {
	// XXX
	return session_find(cd->sess_id);
}

static void ekg2_conneciton_set_error(connection_data_t *cd, GError **err, const gchar *format, ...) {
	static GString *buffer = NULL;
	va_list args;

	if (cd->error)
		g_error_free(cd->error);
	cd->error = g_error_copy(*err);
	g_clear_error(err);

	if (!buffer)
		buffer = g_string_sized_new(256);

	va_start(args, format);
	g_string_vprintf(buffer, format, args);
	va_end(args);

	if (cd->error) {
		g_prefix_error(&cd->error, buffer->str);
		debug_error("%s\n", cd->error->message);
	} else {
		debug_error("%s (null)\n", buffer->str);
	}
}

int ekg2_connection_write(connection_data_t *cd, gconstpointer buffer, gsize length) {
	session_t *s = session_find(cd->sess_id);
	GError *error = NULL;
	gint b_written = 0, count = 0;

	g_return_val_if_fail(cd != NULL, -1);
	g_return_val_if_fail(G_IS_OUTPUT_STREAM(cd->out_stream), -1);
	g_return_val_if_fail(length > 0, -1);

	if (cd->use_out_buf)
		return ekg2_connection_buffer_write(cd, buffer, length);

	while (length > 0) {
		b_written = g_output_stream_write(cd->out_stream, buffer+count, length, NULL, &error);

		if (0 == b_written) {
			ekg2_conneciton_set_error(cd, &error, _("Nothing was written."));
			cd->failure_callback(cd);
			return -1;
		}

		if (b_written < 0) {
			if (g_error_matches(error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK)) {
				debug_warn("Socket send would block.\n");
				g_error_free(error);
				error = NULL;
				continue;
			} else {
				ekg2_conneciton_set_error(cd, &error, _("Error sending to socket: "));
				cd->failure_callback(cd);
				return -1;
			}
		}

		debug_function("[%s] ekg2_connection_write() write %d bytes\n", session_uid_get(s), b_written);

		length -= b_written;
		count += b_written;
	}

	return count;
}

int ekg2_connection_buffer_write(connection_data_t *cd, gconstpointer buffer, gsize length) {
	session_t *s = session_find(cd->sess_id);
	g_return_val_if_fail(cd != NULL, -1);
	g_return_val_if_fail(length > 0, -1);
	g_string_append_len(cd->out_buf, buffer, length);
	debug_function("[%s] ekg2_connection_buffer_write() add %d bytes to buffer. Buffer length=%d\n", session_uid_get(s), length, cd->out_buf->len);
	return length;
}

int ekg2_connection_buffer_flush(connection_data_t *cd) {
	session_t *s = session_find(cd->sess_id);
	int result;

	debug_function("[%s] ekg2_connection_buffer_flush()\n", session_uid_get(s));

	cd->use_out_buf = FALSE;
	result = ekg2_connection_write(cd, cd->out_buf->str, cd->out_buf->len);
	if (cd) g_string_set_size(cd->out_buf, 0);

	return result;
}

static gboolean async_read_callback(GIOChannel *channel, GIOCondition condition, gpointer data) {
	connection_data_t *cd = data;
	gchar	buffer[1024];
	gsize	bytes_read;
	GError	*error = NULL;

	bytes_read = g_input_stream_read(cd->in_stream, buffer, sizeof buffer, NULL, &error);
	if (bytes_read>0) {
		session_t *s = session_find(cd->sess_id);
		g_string_append_len(cd->in_buf, buffer, bytes_read);
		debug_function("[%s] async_read_callback() read %d bytes (%d bytes in buffer)\n", s?session_uid_get(s):"", bytes_read, cd->in_buf->len);
		cd->input_callback(cd, cd->in_buf);
	} else {
		error = g_error_new_literal(EKG_CONNECTION_ERROR, EKG_CONNECTION_ERROR_EOF, _("Connection terminated"));
		ekg2_conneciton_set_error(cd, &error, _("Read stream: "));
		cd->failure_callback(cd);
	}

	return TRUE;
}


static gboolean
accept_certificate(GTlsClientConnection *conn, GTlsCertificate *cert, GTlsCertificateFlags errors, gpointer data) {
	// XXX
	return TRUE;
}


static void ekg2_failure_callback(connection_data_t *cd) {
	session_t *s = ekg2_connection_get_session(cd);
	GError *err = cd->error;

	if (s->disconnecting && g_error_matches(err, EKG_CONNECTION_ERROR, EKG_CONNECTION_ERROR_EOF))
		cd->disconnect_handler(s, NULL, EKG_DISCONNECT_USER);
	else
		cd->disconnect_handler(s, err ? err->message : "", EKG_DISCONNECT_NETWORK);
}

static void ekg2_connect_failure_handler(connection_data_t *cd) {
	session_t *s = ekg2_connection_get_session(cd);
	GError *err = cd->error;

	cd->disconnect_handler(s, err ? err->message : "", EKG_DISCONNECT_FAILURE);
}



static char *socket_address_toa(GSocketAddress *address) {
	static GString *buffer = NULL;
	GInetAddress *inet_addr;
	char *str, *format;

	if (!buffer)
		buffer = g_string_sized_new(256);

	inet_addr = g_inet_socket_address_get_address(G_INET_SOCKET_ADDRESS(address));
	str = g_inet_address_to_string(inet_addr);
	format = (AF_INET6 == g_inet_address_get_family(inet_addr)) ? "[%s]:%d" : "%s:%d";
	g_string_printf(buffer, format, str, g_inet_socket_address_get_port(G_INET_SOCKET_ADDRESS(address)));
	g_free(str);
	return buffer->str;
}

gboolean ekg2_connection_start_tls(connection_data_t *cd) {
	// XXX - add failure_handler support
	GError *error = NULL;
	GIOStream *tls_conn;

	if (!(tls_conn = g_tls_client_connection_new(cd->conn, NULL, &error))) {
		ekg2_conneciton_set_error(cd, &error, _("Could not create TLS connection. "));
		return FALSE;
	}

	g_signal_connect(tls_conn, "accept-certificate", G_CALLBACK(accept_certificate), cd);

	//g_tls_connection_set_certificate(G_TLS_CONNECTION(tls_conn), certificate);

	g_object_unref(cd->conn);
	cd->conn = G_IO_STREAM(tls_conn);

	if (!g_tls_connection_handshake(G_TLS_CONNECTION(tls_conn), NULL, &error)) {
		ekg2_conneciton_set_error(cd, &error, _("Error during TLS handshake. "));
		return FALSE;
	}

	g_source_remove(cd->watch_id);

	cd->in_stream = g_io_stream_get_input_stream(cd->conn);
	cd->out_stream = g_io_stream_get_output_stream(cd->conn);

	cd->watch_id = g_io_add_watch(cd->channel, G_IO_IN, async_read_callback, cd);

	cd->tls = TRUE;

	return TRUE;
}

static gboolean
connection_open(connection_data_t *cd, const char *hostip, int port, GSocketFamily family) {
	GSocketAddress *address = NULL;
	GError	*error = NULL;
	connection_starter_t *cs = cd->cs;

	cd->socket = g_socket_new(family, G_SOCKET_TYPE_STREAM, 0, &error);
	if (NULL == cd->socket) {
		ekg2_conneciton_set_error(cd, &error, "");
		return FALSE;
	}

//	g_socket_set_timeout(cd->socket, timeout);

	if (port <= 0 || port > G_MAXUINT16)
		port = cs->default_port;

	if (AF_INET == family) {
		struct sockaddr_in *ipv4;
		ipv4 = xmalloc(sizeof(struct sockaddr_in));
		ipv4->sin_family = AF_INET;
		ipv4->sin_port = g_htons(port);
		inet_pton(AF_INET, hostip, &(ipv4->sin_addr));
		address = g_socket_address_new_from_native(ipv4, sizeof(struct sockaddr_in));
		g_free(ipv4);
	} else if (AF_INET6 == family) {
		struct sockaddr_in6 *ipv6;
		ipv6 = xmalloc(sizeof(struct sockaddr_in6));
		ipv6->sin6_family = AF_INET6;
		ipv6->sin6_port = g_htons(port);
		inet_pton(AF_INET6, hostip, &(ipv6->sin6_addr));
		address = g_socket_address_new_from_native(ipv6, sizeof(struct sockaddr_in6));
		g_free(ipv6);
	} else {
		debug_error("connection_open(), unknown addr family %d!\n", family);
		return FALSE;
	}

	if (!g_socket_connect(cd->socket, address, NULL, &error)) {
		ekg2_conneciton_set_error(cd, &error, "Connection to %s failed. ", socket_address_toa(address));
		g_object_unref(address);
		return FALSE;
	}

	{	/* debug */
		GSocketAddress *local = g_socket_get_local_address(cd->socket, &error);
		if (!local) {
			ekg2_conneciton_set_error(cd, &error, _("Error getting local address. "), socket_address_toa(address));
			return FALSE;
		}
		debug_ok("Connected to: %s\n", socket_address_toa(address));
		debug_ok("Local address: %s\n", socket_address_toa(local));
		g_object_unref(local);
	}

	g_object_unref(address);

	cd->conn = G_IO_STREAM(g_socket_connection_factory_create_connection(cd->socket));

	if (cd->tls) {
		GIOStream *tls_conn;

		if (!(tls_conn = g_tls_client_connection_new(cd->conn, NULL, &error))) {
			ekg2_conneciton_set_error(cd, &error, _("Could not create TLS connection. "));
			return FALSE;
		}

		g_signal_connect(tls_conn, "accept-certificate", G_CALLBACK(accept_certificate), cd);

		//g_tls_connection_set_certificate(G_TLS_CONNECTION(tls_conn), certificate);

		g_object_unref(cd->conn);
		cd->conn = G_IO_STREAM(tls_conn);

		if (!g_tls_connection_handshake(G_TLS_CONNECTION(tls_conn), NULL, &error)) {
			ekg2_conneciton_set_error(cd, &error, _("Error during TLS handshake. "));
			return FALSE;
		}
	}


	if (cd->conn) {
		cd->in_stream = g_io_stream_get_input_stream(cd->conn);
		cd->out_stream = g_io_stream_get_output_stream(cd->conn);
	}

	cs->connect_handler(cd);

	cd->channel = g_io_channel_unix_new(g_socket_get_fd(cd->socket));
	g_io_channel_set_encoding(cd->channel, NULL, NULL);
	g_io_channel_set_buffered(cd->channel, FALSE);

	cd->watch_id = g_io_add_watch(cd->channel, G_IO_IN, async_read_callback, cd);

	return TRUE;
}

static void aresolv_write_answer(int fd, int what, char *buf) {
	size_t len = xstrlen(buf);
	write(fd, &what, sizeof(what));
	write(fd, &len, sizeof(len));
	write(fd, buf, len);
}

void connect_loop(connection_data_t *cd);

static gboolean aresolv_handler(GIOChannel *channel, GIOCondition condition, gpointer data) {
	/* handle aresolv_write_answer */
	connection_data_t *cd = data;
	connection_starter_t *cs = cd->cs;
	int type;
	size_t len;
	char *buf, *response, **results = NULL;

	read(cs->pipe_in, &type, sizeof(type));
	read(cs->pipe_in, &len, sizeof(len));
	buf = g_malloc0(len+1);
	read(cs->pipe_in, buf, len);
	response = g_strndup(buf, len);
	g_free(buf);

	debug_function("aresolv_handler(%d)\n", type);	// XXX-temp

	if (EKG2_AR_RESOLVER == type) {
		/* resolver answers */
		results = array_make(response, "\n", 0, 0, 0);
		while (results) {
			char *res = array_shift(&results);
			int family = AF_INET;
			char *p = xstrrchr(res, ' ');
			if (p) family=atoi(p+1);
			if (family == cs->prefer_family)
				array_add(&cd->cs->ips, res);
			else
				array_add(&cd->cs->ips2, res);
		}
	} else if (EKG2_AR_SRV == type) {
		/* SRV answers */
		results = array_make(response, "\n", 0, 0, 0);
		while (results)
			array_add(&cd->cs->srvhosts, array_shift(&results));
	} else {
		GError *error = NULL;
		g_set_error_literal(&error, G_IO_ERROR, G_IO_ERROR_FAILED, response);
		ekg2_conneciton_set_error(cd, &error, "");
	}

	g_free(response);
	g_strfreev(results);

	connect_loop(cd);

	return TRUE;
}

static void async_resolvers(connection_data_t *cd, char *query, aresolv_t type) {
	connection_starter_t *cs = cd->cs;
	GPid pid;
	GError *error = NULL;
	GResolver *resolver;
	gchar **results = NULL;
	gchar *response;

	debug_function("async_resolvers(%d)\n", type);		// XXX-tmp

	if (-1 == (pid = fork())) {
		// XXX - add message here
		return;
	}

	if (pid > 0) {
		ekg_child_add(NULL, "async_resolver: %d", pid, NULL, NULL, NULL, pid);
		return;
	}

	/* children */

	resolver = g_resolver_get_default();

	if (EKG2_AR_SRV == type) {
		GList *targets, *item;

		targets = g_resolver_lookup_service(resolver, cs->service, "tcp", cs->domain, NULL, &error);

		for (item=targets; item; item = item->next) {
			GSrvTarget *target = item->data;
			const char *host = g_srv_target_get_hostname(target);
			int port = g_srv_target_get_port(target);

			array_add(&results, saprintf("%s %d", host, port));
		}

		g_resolver_free_targets(targets);
	} else {
		GList *addrs, *item;
		char *port;

		if ((port = xstrchr(query, ' '))) *port++ = 0;	// XXX port separator?

		addrs = g_resolver_lookup_by_name(resolver, query, NULL, &error);

		for (item=addrs; item; item = item->next) {
			GInetAddress *addr = item->data;
			char *ip = g_inet_address_to_string(addr);
			int family = g_inet_address_get_family(addr);

			array_add(&results, saprintf("%s %s %d", ip, (port?port:""), family));
			g_free(ip);
		}
		g_resolver_free_addresses(addrs);
		g_free(query);
	}

	g_object_unref(resolver);

	if (error) {
		aresolv_write_answer(cs->pipe_out, EKG2_AR_ERROR, error->message);
		g_error_free(error);
	} else {
		response = array_join_count(results, "\n", g_strv_length(results));
		aresolv_write_answer(cs->pipe_out, type, response);
		g_free(response);
	}

	g_strfreev(results);

	sleep(1);
	exit(0);
}

void connect_loop(connection_data_t *cd) {
	connection_starter_t *cs = cd->cs;

	if (cs->ips || cs->ips2) {
		char *q;
		while ((q = array_shift(&cs->ips)) || (q = array_shift(&cs->ips2))) {
			char **arg = array_make(q, " ", 3, 0, 0);
			char *hostip = arg[0];
			int port = *arg[1] ? atoi(arg[1]) : cs->port;
			int family = atoi(arg[2]);

			if (connection_open(cd, hostip, port, family)) {
				connect_starter_free(cd);
				g_strfreev(arg);
				return;
			}
			g_strfreev(arg);
			g_free(q);
		}
	}

	if (cs->srvhosts) {
		char *q;
		if ((q = array_shift(&cs->srvhosts))) {
			async_resolvers(cd, q, EKG2_AR_RESOLVER);
			g_free(q);
			return;
		}
	}

	if (cs->servers) {
		char *q, *end, *tmp;
		char *name = NULL, *port = NULL;

		if ((q = array_shift(&cs->servers))) {
			name = q;
			/* parse host and port */
			if (('[' == *q) && (end = strchr(q, ']'))) {
				/* [2001:bad::1]:123 */
				*end = '\0';
				name = q + 1;
				if (*++end == ':')
					port = end + 1;
			} else if ((port = strchr(q, ':')) && !strchr(port + 1, ':')) {
				/*  one ':' in string */
				*port++ = '\0';
			}
			tmp = g_strdup_printf("%s %s", name, port ? port : ekg_itoa(cs->port));

			async_resolvers(cd, tmp, EKG2_AR_RESOLVER);

			g_free(tmp);
			g_free(q);
			return;
		}
	}

	connect_starter_free(cd);
	cs->connect_failure_handler(cd);
}

static void ekg2_connect_common(connection_data_t *cd) {
	session_t *s = session_find(cd->sess_id);
	connection_starter_t *cs = cd->cs;
	const int pref	= session_int_get(s, "prefer_family");

	if (4 == pref)
		cd->cs->prefer_family = G_SOCKET_FAMILY_IPV4;
	else if (6 == pref)
		cd->cs->prefer_family = G_SOCKET_FAMILY_IPV6;

	cs->channel = g_io_channel_unix_new(cs->pipe_in);
	g_io_channel_set_encoding(cs->channel, NULL, NULL);
	g_io_channel_set_buffered(cs->channel, FALSE);
	cs->pipe_watch_id = g_io_add_watch(cs->channel, G_IO_IN, aresolv_handler, cd);

	if (cs->domain)
		async_resolvers(cd, NULL, EKG2_AR_SRV);
	else
		connect_loop(cd);
}

void
ekg2_connection_connect_full(
	connection_data_t *cd,
	ekg2_connect_handler_t connect_handler,
	ekg2_connect_failure_t connect_failure_handler,
	ekg2_connection_input_callback_t input_callback,
	ekg2_connection_failure_t failure_callback)
{
	connection_starter_t *cs = cd->cs;

	cs->connect_handler = connect_handler;
	cs->connect_failure_handler = connect_failure_handler;

	cd->input_callback = input_callback;
	cd->failure_callback = failure_callback;

	ekg2_connect_common(cd);
}

void
ekg2_connection_connect(
		connection_data_t *cd,
		ekg2_connect_handler_t connect_handler,
		ekg2_connection_input_callback_t input_callback,
		ekg2_connection_disconnect_t disconnect_handler)
{
	connection_starter_t *cs = cd->cs;

	cs->connect_handler = connect_handler;
	cs->connect_failure_handler = ekg2_connect_failure_handler;

	cd->input_callback = input_callback;
	cd->failure_callback = ekg2_failure_callback;

	cd->disconnect_handler = disconnect_handler;

	ekg2_connect_common(cd);
}

