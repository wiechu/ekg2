/* $Id$ */

/*
 *  (C) Copyright 2003-2005 Wojtek Kaniewski <wojtekka@irc.pl>
 *			    Tomasz Torcz <zdzichu@irc.pl>
 *			    Leszek Krupiński <leafnode@pld-linux.org>
 *			    Piotr Pawłow and other libtlen developers (http://libtlen.sourceforge.net/index.php?theme=teary&page=authors)
 *		       2012 Wiesław Ochmiński <wiechu at wiechu dot com>
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

#include <sys/types.h>

#ifndef NO_POSIX_SYSTEM
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#endif

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>

#ifndef NO_POSIX_SYSTEM
#include <netdb.h>
#endif

#ifdef __sun	  /* Solaris, thanks to Beeth */
#include <sys/filio.h>
#endif

#ifdef HAVE_LIBZ
# include "zlib.h"
#endif

#include "jabber.h"
#include "jabber_dcc.h"

char *jabber_default_search_server = NULL;
char *jabber_default_pubsub_server = NULL;
int config_jabber_beep_mail = 0;
int config_jabber_disable_chatstates = EKG_CHATSTATE_ACTIVE | EKG_CHATSTATE_GONE;
const char *jabber_authtypes[] = { "none", "from", "to", "both" };

static int session_postinit;
static int jabber_theme_init();
PLUGIN_DEFINE(jabber, PLUGIN_PROTOCOL, jabber_theme_init);

/**
 * jabber_session_init()
 *
 * Handler for: <i>SESSION_ADDED</i><br>
 * Init priv_data session struct jabber_private_t if @a session is jabber one.
 *
 * @param ap 1st param: <i>(char *) </i><b>session</b> - uid of session
 * @param data NULL
 *
 * @return	0 if @a session is jabber one, and we init memory<br>
 *		1 if we don't found such session, or it wasn't jabber session <b>[most probable]</b>, or we already init memory.
 */

static QUERY(jabber_session_init) {
	char *session = *(va_arg(ap, char**));

	session_t *s = session_find(session);
	jabber_private_t *j;

	if (!s || s->plugin != &jabber_plugin || s->priv)
		return 1;

	j = xmalloc(sizeof(jabber_private_t));
	j->istlen = (tolower(s->uid[0]) == 't');	/* mark if this is tlen protocol */

	if (!j->istlen)
		ekg_recode_utf8_inc();
	else
		ekg_recode_iso2_inc();

	s->priv = j;

	return 0;
}


/**
 * jabber_session_deinit()
 *
 * Handler for: <i>SESSION_REMOVED</i><br>
 * Free memory allocated by jabber_private_t if @a session is jabber one.
 *
 * @param ap 1st param: <i>(char *) </i><b>session</b> - uid of session
 * @param data NULL
 *
 * @return	0 if @a session is jabber one, and memory allocated where xfree()'d.<br>
 *		1 if not such session, or it wasn't jabber session <b>[most probable]</b>, or we already free memory.
 */

static QUERY(jabber_session_deinit) {
	char *session = *(va_arg(ap, char**));

	session_t *s = session_find(session);
	jabber_private_t *j;
	jabber_conversation_t *thr, *next;

	if (!s || s->plugin != &jabber_plugin || !(j = s->priv))
		return 1;

	s->priv = NULL;

	if (!j->istlen)
		ekg_recode_utf8_dec();
	else
		ekg_recode_iso2_dec();

	xfree(j->server);
	xfree(j->resource);
	xfree(j->last_gmail_result_time);
	xfree(j->last_gmail_tid);

	if (j->parser)
		XML_ParserFree(j->parser);
	jabber_bookmarks_free(j);
	jabber_privacy_free(j);
	jabber_iq_stanza_free(j);

		/* conversations */
	for (thr = j->conversations; thr; thr = next) {
		next = thr->next; /* we shouldn't rely on freed thr->next */

		xfree(thr->thread);
		xfree(thr->subject);
		xfree(thr->uid);
		xfree(thr);
	}

	xfree(j);

	return 0;
}

static LIST_FREE_ITEM(list_jabber_stanza_free, jabber_stanza_t *) {
	xfree(data->id);
	xfree(data->to);
	xfree(data->type);
	xfree(data->xmlns);
	xfree(data);
}

int jabber_iq_stanza_free(jabber_private_t *j) {
	if (!j || !j->iq_stanzas) return -1;

	LIST_DESTROY(j->iq_stanzas, list_jabber_stanza_free);
	j->iq_stanzas = NULL;
	return 0;
}

int jabber_stanza_freeone(jabber_private_t *j, jabber_stanza_t *stanza) {
	if (!j || !stanza) return -1;

	LIST_REMOVE(&(j->iq_stanzas), stanza, list_jabber_stanza_free);
	return 0;
}

LIST_ADD_COMPARE(jabber_privacy_add_compare, jabber_iq_privacy_t *) {
	return (data1->order - data2->order);
}

static LIST_FREE_ITEM(list_jabber_privacy_free, jabber_iq_privacy_t *) {
	xfree(data->type);
	xfree(data->value);
	xfree(data);
}

/* destroy all previously saved jabber:iq:privacy list... we DON'T DELETE LIST on jabberd server... only list saved @ j->privacy */

int jabber_privacy_free(jabber_private_t *j) {
	if (!j || !j->privacy) return -1;

	LIST_DESTROY(j->privacy, list_jabber_privacy_free);
	j->privacy = NULL;
	return 0;
}

int jabber_privacy_freeone(jabber_private_t *j, jabber_iq_privacy_t *item) {
	if (!j || !item) return -1;

	LIST_REMOVE(&(j->privacy), item, list_jabber_privacy_free);
	return 0;
}

static LIST_FREE_ITEM(list_jabber_bookmarks_free, jabber_bookmark_t *) {
	if (data->type == JABBER_BOOKMARK_URL) { xfree(data->priv_data.url->name); xfree(data->priv_data.url->url); }
	else if (data->type == JABBER_BOOKMARK_CONFERENCE) {
		xfree(data->priv_data.conf->name); xfree(data->priv_data.conf->jid);
		xfree(data->priv_data.conf->nick); xfree(data->priv_data.conf->pass);
	}
	xfree(data->priv_data.other);
	xfree(data);
}

/* destroy all previously saved bookmarks... we DON'T DELETE LIST on jabberd server... only list saved @ j->bookamarks */
int jabber_bookmarks_free(jabber_private_t *j) {
	if (!j || !j->bookmarks) return -1;

	LIST_DESTROY(j->bookmarks, list_jabber_bookmarks_free);
	j->bookmarks = NULL;
	return 0;
}

/**
 * jabber_print_version()
 *
 * handler for: <i>PLUGIN_PRINT_VERSION</i><br>
 * Print expat version
 *
 * @return 0
 */

static QUERY(jabber_print_version) {
	print("generic", XML_ExpatVersion());
	return 0;
}

/**
 * jabber_validate_uid()
 *
 * handler for: <i>PROTOCOL_VALIDATE_UID</i><br>
 * checks, if @a uid is <i>proper for jabber plugin</i>.
 *
 * @note <i>Proper for jabber plugin</i> means either:
 *	- If @a uid starts with xmpp: have got '@' (but xmpp:@ is wrong) and after '@' there is at least one char	[<b>xmpp protocol</b>]<br>
 *	- If @a uid starts with tlen: (and len > 5)								[<b>tlen protocol</b>]
 *
 * @param ap 1st param: <i>(char *) </i><b>uid</b>  - of user/session/command/whatever
 * @param ap 2nd param: <i>(int) </i><b>valid</b> - place to put 1 if uid is valid for jabber plugin.
 * @param data NULL
 *
 * @return	-1 if it's valid uid for jabber plugin<br>
 *		 0 if not
 */

static QUERY(jabber_validate_uid) {
	char *uid = *(va_arg(ap, char **));
	int *valid = va_arg(ap, int *);

	if (!uid)
		return 0;

	/* XXX: think about 'at' in jabber UIDs */

	if (!xstrncasecmp(uid, "xmpp:", 5) || !xstrncasecmp(uid, "tlen:", 5)) {
		(*valid)++;
		return -1;
	}

	return 0;
}

static QUERY(jabber_window_kill) {
	window_t	*w = *va_arg(ap, window_t **);
	jabber_private_t *j;
	newconference_t  *c;

	char *status = NULL;

	if (w && w->id && w->target && session_check(w->session, 1, "xmpp") && (c = newconference_find(w->session, w->target)) &&
			(j = jabber_private(w->session)) && session_connected_get(w->session)) {
														/* XXX: check really needed? vv */
		jabber_write(w->session, "<presence to='%s/%s' type='unavailable'>%s</presence>", w->target + 5, c->priv_data, status ? status : "");
		newconference_destroy(c, 0);
	}

	return 0;
}

int jabber_write_status(session_t *s) {
	#define JABBER_EKG_CAPS ""

	jabber_private_t *j = session_private_get(s);
	int prio = session_int_get(s, "priority");
	int status;
	char *descr;
	char *real = NULL;
	char *priority = NULL;
	char *x_signed = NULL;
	char *x_vcard = NULL;

	if (!s || !j)
		return -1;

	if (!session_connected_get(s))
		return 0;

	status = session_status_get(s);
	/*if (!xstrcmp(status, EKG_STATUS_AUTOAWAY)) status = "away"; (that shouldn't take place...)*/

	if ((descr = tlenjabber_escape(session_descr_get(s)))) {
		real = saprintf("<status>%s</status>", descr);
		xfree(descr);
	}

	if (!j->istlen) {
		const char *tmp;

		priority = saprintf("<priority>%d</priority>", prio); /* priority only in real jabber session */

		if (session_int_get(s, "__gpg_enabled") == 1) {
			char *signpresence;

			signpresence = xstrdup(session_descr_get(s));	/* XXX, data in unicode required (?) */
			if (!signpresence)
				signpresence = xstrdup("");

			signpresence = jabber_openpgp(s, NULL, JABBER_OPENGPG_SIGN, signpresence, NULL, NULL);
			if (signpresence) {
				x_signed = saprintf("<x xmlns='jabber:x:signed'>%s</x>", signpresence);
				xfree(signpresence);
			}
		}

		if ((tmp = session_get(s, "photo_hash")))
			x_vcard = saprintf("<x xmlns='vcard-temp:x:update'><photo>%s</photo></x>", tmp);
	}
#define P(x) (x ? x : "")
	if (!j->istlen && (status == EKG_STATUS_AVAIL))
		jabber_write(s, "<presence>%s%s%s%s%s</presence>", P(real), P(priority), P(x_signed), P(x_vcard), JABBER_EKG_CAPS);
	else if (status == EKG_STATUS_INVISIBLE)
		jabber_write(s, "<presence type='invisible'>%s%s</presence>", P(real), P(priority));
	else {
		const char *status_s;

		if (j->istlen && (status == EKG_STATUS_AVAIL)) status_s = "available";
		else status_s = ekg_status_string(status, 0);
		jabber_write(s, "<presence><show>%s</show>%s%s%s%s%s</presence>", status_s, P(real), P(priority), P(x_signed), P(x_vcard), JABBER_EKG_CAPS);
	}
#undef P

	xfree(priority);
	xfree(real);
	xfree(x_signed);
	xfree(x_vcard);
	return 0;
}

void jabber_handle_disconnect(session_t *s, const char *reason, int type) {
	jabber_private_t *j;

	if (!s || !(j = s->priv))
		return;

	if (!s->connected && !s->connecting)
		return;

	ekg2_connection_close(&j->connection);

	protocol_disconnected_emit(s, reason, type);

	j->using_compress = JABBER_COMPRESSION_NONE;

	jabber_iq_stanza_free(j);

	if (j->parser)
		XML_ParserFree(j->parser);
	j->parser = NULL;

	{
		window_t *wl;

		for (wl = windows; wl; wl = wl->next) {
			window_t *w = wl;

			if (w->session == s) {
				const char *tmp = get_uid(s, w->target);

				if (tmp != w->target) {
					xfree(w->target);
					w->target = xstrdup(tmp);
				}
			}
		}

		userlist_free(s);
		query_emit(NULL, "userlist-refresh");
	}

	session_set(s, "__sasl_excepted", NULL);
	session_int_set(s, "__roster_retrieved", 0);
	session_int_set(s, "__session_need_start", 0);
}

static void xmlnode_handle_start(void *data, const char *name, const char **atts) {
	session_t *s = (session_t *) data;
	jabber_private_t *j;

	if (!s || !(j = s->priv) || !name) {
		debug_error("[%] xmlnode_handle_start() invalid parameters\n", session_uid_get(s));
		return;
	}

	/* XXX, czy tego nie mozna parsowac tak jak wszystko inne w jabber_handle() ?
	 *	A tutaj tylko tworzyc drzewo xmlowe?
	 *	XXX, rtfm expat
	 */

	if (!(s->connected) && (j->istlen ? !xstrcmp(name, "s") : !xstrcmp(name, "http://etherx.jabber.org/streams\033stream"))) {
		const char *passwd	= session_get(s, "password");

		char *username, *tmp;

		if ((tmp = xstrchr(s->uid + 5, '@')))
			username = xstrndup(s->uid + 5, tmp - s->uid - 5);
		else	username = xstrdup(s->uid + 5);

			/* XXX,
			 *	Here if we've got SASL-connection we should do jabber:iq:register only when
			 *	j->connecting == 1,
			 *
			 *	but i'm not quite sure if s->connected, and j->connecting can be 0	[yeap, i know it would be stupid]
			 *	So, to avoid regression, we use here j->connecting != 2
			 */

		if (j->istlen) {
			/* Tlen Authentication */
			char *resource = tlenjabber_escape(j->resource);/* escaped resource name */
			jabber_write(s, "<iq type='set' id='auth' to='%s'><query xmlns='jabber:iq:auth'>"
					"<host>tlen.pl</host>"
					"<username>%s</username>"
					"<digest>%s</digest>"
					"<resource>%s</resource></query></iq>",
					j->server, username, tlen_auth_digest(jabber_attr((char **) atts, "i"), passwd), resource);
			g_free(resource);
		} else if (!j->sasl_connecting && session_get(s, "__new_account")) {
			char *epasswd	= jabber_escape(passwd);
			jabber_write(s,
				"<iq type='set' to='%s' id='register%d'>"
				"<query xmlns='jabber:iq:register'><username>%s</username><password>%s</password></query></iq>",
				j->server, j->id++, username, epasswd ? epasswd : ("foo"));

			xfree(epasswd);
		}


		xfree(username);
	} else {
		xmlnode_t *n, *newnode;
		int arrcount, i;

		newnode = xmalloc(sizeof(xmlnode_t));

		{		/* get the namespace */
			char *x		= NULL;
			char *tmp	= xstrdup(name);
			char *sep	= xstrchr(tmp, '\033');
			if (sep) {
				*sep	= '\0';
				name	= ++sep;
				x	= tmp;
			}

			newnode->name = xstrdup(name);
			newnode->xmlns = xstrdup(x);
			xfree(tmp);
		}

		if ((n = j->node)) {
			newnode->parent = n;

			if (!n->children)
				n->children = newnode;
			else {
				xmlnode_t *m = n->children;

				while (m->next)
					m = m->next;

				m->next = newnode;
			}
		}
		arrcount = g_strv_length((char **) atts);

		if (arrcount > 0) {		/* we don't need to allocate table if arrcount = 0 */
			newnode->atts = xmalloc((arrcount + 1) * sizeof(char *));
			for (i = 0; i < arrcount; i++)
				newnode->atts[i] = xstrdup(atts[i]);
		}

		j->node = newnode;
	}
}


static void jabber_handle_stream(connection_data_t *cd, GString *buffer) {
	session_t *s = ekg2_connection_get_session(cd);
	jabber_private_t *j;
	XML_Parser parser;				/* j->parser */
	char *uncompressed	= NULL;
	char *buf;
	int len;
	int rlen;

	/* session dissapear, shouldn't happen */
	if (!s || !(j = s->priv))
		return;

/*	s->activity = time(NULL); */

	debug_function("[%s]_handle_stream()\n", session_uid_get(s));

	parser = j->parser;

	len = buffer->len;
	if (!(buf = XML_GetBuffer(parser, len + 1))) {
		jabber_handle_disconnect(s, "XML_GetBuffer failed", EKG_DISCONNECT_NETWORK);
		return;
	}

	strncpy(buf, buffer->str, len);
	g_string_set_size(buffer, 0);

	buf[len] = 0;
	rlen = len;

	switch (j->using_compress) {
		case JABBER_COMPRESSION_ZLIB:
#ifdef HAVE_LIBZ
			uncompressed = jabber_zlib_decompress(buf, &rlen);
#else
			debug_error("[%s] jabber_handle_stream() compression zlib, but no zlib support.. you're joking, right?\n", session_uid_get(s));
#endif
			break;

		case JABBER_COMPRESSION_LZW:
			debug_error("[%s] jabber_handle_stream() j->using_compress XXX implement LZW!\n", session_uid_get(s));
			break;

		case JABBER_COMPRESSION_NONE:
		case JABBER_COMPRESSION_LZW_INIT:
		case JABBER_COMPRESSION_ZLIB_INIT:
			break;

		default:
			debug_error("[%s] jabber_handle_stream() j->using_compress wtf? unknown! %d\n", session_uid_get(s), j->using_compress);
	}

	debug_iorecv("[%s] (%db/%db) recv: %s\n", session_uid_get(s), rlen, len, uncompressed ? uncompressed : buf);
/*
	if (uncompressed) {
		memcpy(buf, uncompressed, rlen);
	}
 */

	if (!XML_ParseBuffer(parser, rlen, (rlen == 0)))
//	if (!XML_Parse(parser, uncompressed ? uncompressed : buf, rlen, (rlen == 0)))
	{
		char *tmp;

		tmp = format_string(format_find("jabber_xmlerror_disconnect"), XML_ErrorString(XML_GetErrorCode(parser)));

		if ((!j->parser && parser) || (parser != j->parser)) XML_ParserFree(parser);

		jabber_handle_disconnect(s, tmp, EKG_DISCONNECT_NETWORK);
		xfree(tmp);

		xfree(uncompressed);
		return;
	}
	if ((!j->parser && parser) || (parser != j->parser)) XML_ParserFree(parser);
	xfree(uncompressed);

}

static TIMER_SESSION(jabber_ping_timer_handler) {
	jabber_private_t *j;

	if (type == 1)
		return 0;

	if (!s || !s->priv || !s->connected) {
		return -1;
	}

	j = jabber_private(s);
	if (j->istlen) {
		jabber_write(s, "  \t  ");	/* ping according to libtlen */
		return 0;
	}

	if (session_int_get(s, "ping_server") == 0) return -1;

		/* XEP-0199 */
	jabber_write(s, "<iq to='%s' id='ping%d' type='get'><ping xmlns='urn:xmpp:ping'/></iq>\n",
			j->server, j->id++);
	return 0;
}


static void jabber_handle_connect(connection_data_t *cd) {
	session_t *s = ekg2_connection_get_session(cd);
	jabber_private_t *j = jabber_private(s);

	debug_function("[%s]_handle_connect()", session_uid_get(s));


	session_int_set(s, "__roster_retrieved", 0);

	j->using_compress = JABBER_COMPRESSION_NONE;

	if (!(j->istlen)) {
		jabber_write(s, "<?xml version='1.0' encoding='utf-8'?><stream:stream to='%s' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>",
				j->server);
	} else {
		jabber_write(s, "<s v='2'>");
	}

	j->id = 1;
	j->parser = jabber_parser_recreate(NULL, s);

	if (j->istlen || (session_int_get(s, "ping_server") != 0)) {
		if (timer_find_session(s, "ping") == NULL) {
			/* w/g dokumentacji do libtlen powinnismy wysylac pinga co 60 sekund */
			timer_add_session(s, "ping", j->istlen ? 60 : 180, 1, jabber_ping_timer_handler);
		}
	}

	return;
}

static void jabber_handle_stream_tlen_hub(connection_data_t *cd, GString *buffer) {
	session_t *s = ekg2_connection_get_session(cd);
	jabber_private_t *j = jabber_private(s);
	char *header, *body, *buf;

	/* libtlen */

	buf = buffer->str;

	header	= xstrstr(buf, "\r\n");
	body	= xstrstr(buf, "\r\n\r\n");
	if (header && body) {
		*header = '\0';
		body += 4;
		debug_function("[TLEN, HUB]: %s / %s\n", buf, body);
		if (!xstrstr(buf, " 200 "))
			return;	// XXX

		/* XXX: use XML parser instead of hardcoded lengths */
		/* <t s='s1.tlen.pl' p='443' v='91' c='0' i='83.20.106.210'>91</t> */
		{
			char *end, *endb;

			body += 6;
			if ((end = xstrchr(body, '\''))) {
				*end	= 0;
				end	+= 5;
				if ((endb = xstrchr(end, '\'')))
					*endb	= 0;

				const int newport	= atoi(end);
				if (newport != 0)
					j->port	= newport;
			}
		}

		debug_function("[%s, HUB]: host = %s, port = %d\n", session_uid_get(s), body, j->port);

		ekg2_connection_close(&j->connection);

		j->connection = cd = ekg2_connection_new(s, j->port);

		ekg2_connection_set_servers(cd, body);

		ekg2_connection_connect(cd,
			jabber_handle_connect,
			jabber_handle_stream,
			jabber_handle_disconnect);

		return;
	}
}

static void jabber_handle_connect_tlen_hub(connection_data_t *cd) {	/* tymczasowy */
	session_t *s = ekg2_connection_get_session(cd);
	jabber_private_t *j = jabber_private(s);
	char *esc;

	debug_function("[%s]_handle_connect_tlen_hub()", session_uid_get(s));

	j->istlen = 1;		/* reset */

	esc = tlen_encode(s->uid+5);
	jabber_write(s, "GET /4starters.php?u=%s&v=10 HTTP/1.0\r\nHost: %s\r\n\r\n", esc, TLEN_HUB);	/* libtlen */
	xfree(esc);
}

COMMAND(jabber_command_connect) {
	const char *realserver	= session_get(session, "server");
	const char *resource	= session_get(session, "resource");
	const char *server;

	jabber_private_t *j = session_private_get(session);

	if (session->connecting) {
		printq("during_connect", session_name(session));
		return -1;
	}

	if (session_connected_get(session)) {
		printq("already_connected", session_name(session));
		return -1;
	}

	if (!session_get(session, "__new_account") && !(session_get(session, "password"))) {
		printq("no_config");
		return -1;
	}

	if (command_exec(NULL, session, "/session --lock", 0) == -1)
		return -1;

	debug("[%s]_command_connect\n", session->uid);
		/* XXX, nie wymagac od usera podania calego uida w postaci: tlen:ktostam@tlen.pl tylko samo tlen:ktostam? */
	if (!(server = xstrchr(session->uid, '@'))) {
		printq("wrong_id", session->uid);
		return -1;
	}

	xfree(j->server);
	j->server = xstrdup(++server);

	if (!realserver) {
		if (j->istlen) {
			j->istlen++;
			realserver = TLEN_HUB;
		} else
			realserver = server;
	}

	{
		connection_data_t *cd;
		int port = session_int_get(session, "port");
		int ssl_port = session_int_get(session, "ssl_port");
		int use_ssl = session_int_get(session, "use_ssl");

		if (j->istlen && !xstrcmp(realserver, TLEN_HUB))
			j->port = 80;
		else if (use_ssl) {
			j->port = ssl_port < 1 ? 5223 : ssl_port;
		} else {
			j->port = port < 1 ? 5222 : port;
		}

		j->connection = cd = ekg2_connection_new(session, j->port);

		ekg2_connection_set_servers(cd, realserver);

		ekg2_connection_set_tls(cd, 1 == use_ssl);

		if (!j->istlen && !use_ssl)
			ekg2_connection_set_srv(cd, "xmpp-client", j->server);

		ekg2_connection_connect(cd,
			(j->istlen>1) ? jabber_handle_connect_tlen_hub : jabber_handle_connect,
			(j->istlen>1) ? jabber_handle_stream_tlen_hub : jabber_handle_stream,
			jabber_handle_disconnect);

	}

	if (!resource)
		resource = JABBER_DEFAULT_RESOURCE;

	xfree(j->resource);
	j->resource = xstrdup(resource);

	session->connecting = 1;
	j->sasl_connecting = 0;

	printq("connecting", session_name(session));
	if (session_status_get(session) == EKG_STATUS_NA)
		session_status_set(session, EKG_STATUS_AVAIL);
	return 0;
}


XML_Parser jabber_parser_recreate(XML_Parser parser, void *data) {
/*	debug_function("jabber_parser_recreate() 0x%x 0x%x\n", parser, data); */

	if (!parser)	parser = XML_ParserCreateNS("UTF-8", '\033');		/*   new parser */
	else		XML_ParserReset(parser, "UTF-8");			/* reset parser */

	XML_SetUserData(parser, (void*) data);
	XML_SetElementHandler(parser, (XML_StartElementHandler) xmlnode_handle_start, (XML_EndElementHandler) xmlnode_handle_end);
	XML_SetCharacterDataHandler(parser, (XML_CharacterDataHandler) xmlnode_handle_cdata);

	return parser;
}

static QUERY(jabber_protocol_ignore) {
	char *sesion	= *(va_arg(ap, char **));
	char *uid	= *(va_arg(ap, char **));
/*
	int oldlvl	= *(va_arg(ap, int *));
	int newlvl	= *(va_arg(ap, int *));
*/
	session_t *s	= session_find(sesion);

	/* check this just to be sure... */
	if (session_check(s, 1, "xmpp"))
		/* SPOT rule, first of all here was code to check sesion, valid user, etc...
		 *	then send jabber:iq:roster request... with all new & old group...
		 *	but it was code copied from modify command handler... so here it is.
		 */
		command_exec_format(NULL, s, 0, ("/xmpp:modify %s -x"), uid);

	return 0;
}

static QUERY(jabber_status_show_handle) {
	char *uid	= *(va_arg(ap, char**));
	session_t *s	= session_find(uid);
	jabber_private_t *j = session_private_get(s);
	userlist_t *u;
	char *fulluid;
	char *tmp;

	if (!s || !j)
		return -1;

	fulluid = saprintf("%s/%s", uid, j->resource);

	// nasz stan
	if ((u = userlist_find(s, uid)) && u->nickname)
		print("show_status_uid_nick", fulluid, u->nickname);
	else
		print("show_status_uid", fulluid);

	xfree(fulluid);

	// nasz status
	tmp = (s->connected) ?
		format_string(format_find(ekg_status_label(s->status, s->descr, "show_status_")),s->descr, "") :
		format_string(format_find("show_status_notavail"), "");

	print("show_status_status_simple", tmp);
	xfree(tmp);

	// serwer
	print((session_int_get(s, "use_tls") || session_int_get(s, "use_ssl")) ? "show_status_server_tls" : "show_status_server", j->server, ekg_itoa(j->port));

	if (session_int_get(s, "__gpg_enabled") == 1)
		print("jabber_gpg_sok", session_name(s), session_get(s, "gpg_key"));

	if (s->connecting)
		print("show_status_connecting");

	return 0;
}

static int jabber_theme_init() {
#ifndef NO_DEFAULT_THEME
	/* USERLIST_INFO */
	format_add("user_info_auth_type", _("%K| %nSubscription type: %T%1%n\n"), 1);

	format_add("jabber_xmlerror_disconnect", _("Error parsing XML: %R%1%n"), 1);

	format_add("jabber_msg_failed",		_("%! Message to %T%1%n can't be delivered: %R(%2) %r%3%n\n"),1);
	format_add("jabber_msg_failed_long",	_("%! Message to %T%1%n %y(%n%K%4(...)%y)%n can't be delivered: %R(%2) %r%3%n\n"),1);

	format_add("jabber_unknown_resource", _("%! (%1) User's resource unknown%n\n\n"), 1);
	format_add("jabber_status_notavail", _("%! (%1) Unable to check version, because %2 is unavailable%n\n"), 1);

	format_add("jabber_remotecontrols_preparing",	_("%> (%1) Remote client: %W%2%n is preparing to execute command @node: %W%3"), 1);	/* %2 - uid %3 - node */
	format_add("jabber_remotecontrols_commited",	_("%> (%1) Remote client: %W%2%n executed command @node: %W%3"), 1);			/* %2 - uid %3 - node */
	format_add("jabber_remotecontrols_commited_status", _("%> (%1) RC %W%2%n: requested changing status to: %3 %4 with priority: %5"), 1);	/* %3 - status %4 - descr %5 - prio */
		/* %3 - command+params %4 - sessionname %5 - target %6 - quiet */
	format_add("jabber_remotecontrols_commited_command",_("%> (%1) RC %W%2%n: requested command: %W%3%n @ session: %4 window: %5 quiet: %6"), 1);

	format_add("jabber_form_title",		  "%g,+=%G----- %3 %n(%T%2%n)", 1);
	format_add("jabber_form_item",		  "%g|| %n%(21)3 (%6) %K|%n --%4 %(20)5", 1);	/* %3 - label %4 - keyname %5 - value %6 - req; optional */

	format_add("jabber_form_item_beg",	  "%g|| ,+=%G-----%n", 1);
	format_add("jabber_form_item_plain",	  "%g|| | %n %3: %5", 1);			/* %3 - label %4 - keyname %5 - value */
	format_add("jabber_form_item_end",	  "%g|| `+=%G-----%n", 1);

	format_add("jabber_form_item_val",	  "%K[%b%3%n %g%4%K]%n", 1);			/* %3 - value %4 - label */
	format_add("jabber_form_item_sub",	  "%g|| %|%n\t%3", 1);			/* %3 formated jabber_form_item_val */

	format_add("jabber_form_command",	_("%g|| %nType %W/%3 %g%2 %W%4%n"), 1);
	format_add("jabber_form_instructions",	  "%g|| %n%|%3", 1);
	format_add("jabber_form_description",	  "%g|| %n%|%3", 1);
	format_add("jabber_form_end",		_("%g`+=%G----- End of this %3 form ;)%n"), 1);

	format_add("jabber_registration_item",	  "%g|| %n	      --%3 %4%n", 1); /* %3 - keyname %4 - value */ /* XXX, merge */

	/* simple XEP-0071 - XML parsing error */
	format_add("jabber_msg_xmlsyntaxerr",	_("%! Expat syntax-checking failed on your message: %T%1%n. Please correct your code or use double ^R to disable syntax-checking."), 1);
	/* %1 - session %2 - message %3 - start %4 - end */
	format_add("jabber_vacation", _("%> You'd set up your vacation status: %g%2%n (since: %3 expires@%4)"), 1);

	/* %1 - sessionname %2 - mucjid %3 - nickname %4 - text %5 - atr */
	format_add("jabber_muc_recv",	"%B<%w%X%5%3%B>%n %4", 1);
	format_add("jabber_muc_send",	"%B<%n%X%5%W%3%B>%n %4", 1);
	format_add("jabber_muc_me",	"%y*%X%5%3%B%n %4", 1);
	format_add("jabber_muc_me_sent","%Y*%X%5%3%B%n %4", 1);

	/* %1 - sessionname, %2 - mucjid %3 - text */
	format_add("jabber_muc_notice", "%n-%P%2%n- %3", 1);

	format_add("jabber_muc_room_created", _("%> Room %W%2%n created, now to configure it: type %W/admin %g%2%n to get configuration form, or type %W/admin %g%2%n --instant to create instant one"), 1);
	format_add("jabber_muc_banlist", _("%g|| %n %5 - %W%2%n: ban %c%3%n [%4]"), 1);	/* %1 sesja %2 kanal %3 kto %4 reason %5 numerek */
#if 0
	format_add("jabber_send_chan", _("%B<%W%2%B>%n %5"), 1);
	format_add("jabber_send_chan_n", _("%B<%W%2%B>%n %5"), 1);

	format_add("jabber_recv_chan", _("%b<%w%2%b>%n %5"), 1);
	format_add("jabber_recv_chan_n", _("%b<%w%2%b>%n %5"), 1);
#endif
		/* %1 sesja %2 nick %3 - jid %4 - kanal %6 - role %7 affiliation*/
	format_add("muc_joined",	_("%> %C%2%n %B[%c%3%B]%n has joined %W%4%n as a %g%6%n and a %g%7%n"), 1);
		/* %1 sesja %2 nick %3 - jid %4 - kanal %5 - reason */
	format_add("muc_left",		_("%> %c%2%n [%c%3%n] has left %W%4 %n[%5]\n"), 1);

	format_add("gmail_new_mail",	  _("%> (%1) Content of your mailbox have changed or new mail arrived."), 1);	/* sesja */
	format_add("gmail_count",	  _("%> (%1) You have %T%2%n new thread(s) on your gmail account."), 1);	/* sesja, mail count */
	format_add("gmail_mail",	  "%>	 %|%T%2%n - %g%3%n - %c%5%\n", 1);					/* sesja, from, topic, [UNUSED messages count in thread (?1)], snippet */
	format_add("gmail_thread",	  "%>	 %|%T%2 [%4]%n - %g%3%n\n", 1);						/* sesja, from, topic, messages count in thread */
	format_add("tlen_mail",		_("%> (%1) New mail from %T%2%n, with subject: %G%3%n"), 1);			/* sesja, from, topic */
	format_add("tlen_alert",	_("%> (%1) %T%2%n sent us an alert ...%n"), 1);					/* sesja, from */
	format_add("tlen_alert_send",	_("%> (%1) We send alert to %T%2%n"), 1);					/* sesja, to */

	format_add("jabber_remotecontrols_executing",	_("%> (%1) Executing command: %W%3%n @ %W%2%n (%4)"), 1);
	format_add("jabber_remotecontrols_completed",	_("%> (%1) Command: %W%3%n @ %W%2 %gcompleted"), 1);

	format_add("jabber_iq_stanza",			_("%> (%1) %gIQ: <%W%2 %gxmlns='%W%3%g' to='%W%4%g' id='%W%5%g'>"), 1);

/* auth */
	format_add("jabber_auth_subscribe",	_("%> (%2) %T%1%n asks for authorisation. Use \"/auth -a %1\" to accept, \"/auth -d %1\" to refuse.%n\n"), 1);
	format_add("jabber_auth_unsubscribe",	_("%> (%2) %T%1%n asks for removal. Use \"/auth -d %1\" to delete.%n\n"), 1);
	format_add("jabber_auth_request",	_("%> (%2) Sent authorisation request to %T%1%n.\n"), 1);
	format_add("jabber_auth_accept",	_("%> (%2) Authorised %T%1%n.\n"), 1);
	format_add("jabber_auth_unsubscribed",	_("%> (%2) Asked %T%1%n to remove authorisation.\n"), 1);
	format_add("jabber_auth_cancel",	_("%> (%2) Authorisation for %T%1%n revoked.\n"), 1);
	format_add("jabber_auth_denied",	_("%> (%2) Authorisation for %T%1%n denied.\n"), 1);
	format_add("jabber_auth_probe",		_("%> (%2) Sent presence probe to %T%1%n.\n"), 1);
	format_add("jabber_auth_rejectnoreq",	_("%! (%2) No pending authorization request from %T%1%n. Use \"/auth -d %1\" to force unauth.\n"), 1);
	format_add("jabber_auth_acceptnoreq",	_("%> %|(%2) No pending authorization request from %T%1%n. Permission has been sent, but the user would probably need to request one first.\n"), 1);

		/* XXX: some table? different coloring of different request types? */
	format_add("jabber_auth_list_req",	_("%> (%1) Pending authorization requests:\n"), 1);
	format_add("jabber_auth_list_unreq",	_("%> (%1) Pending removal requests:\n"), 1);
	format_add("jabber_auth_list",		_("%) - %G%1%n\n"), 1);
	format_add("jabber_auth_list_empty",	_("%> (%1) No pending requests."), 1);

/* conversations */
	format_add("jabber_conversations_begin",	_("%g,+=%G--%n (%1) %GAvailable Reply-IDs:%n"), 1);
	format_add("jabber_conversations_item",		_("%g|| %n %1 - %W%2%n (%g%3%n [%c%4%n])"), 1);		/* %1 - n, %2 - user, %3 - subject, %4 - thread */
	format_add("jabber_conversations_end",		_("%g`+=%G-- End of the available Reply-ID list%n"), 1);
	format_add("jabber_conversations_nothread",	_("non-threaded"), 1);
	format_add("jabber_conversations_nosubject",	_("[no subject]"), 1);
	format_add("jabber_gone",			_("%> (%1) User %G%2%n has left the conversation."), 1);

/* gpg */
	format_add("jabber_gpg_plugin",	_("%> (%1) To use OpenGPG support in jabber, first load gpg plugin!"), 1);	/* sesja */
	format_add("jabber_gpg_config",	_("%> (%1) First set gpg_key and gpg_password before turning on gpg_active!"), 1); /* sesja */
	format_add("jabber_gpg_ok",	_("%) (%1) GPG support: %gENABLED%n using key: %W%2%n"), 1);			/* sesja, klucz */
	format_add("jabber_gpg_sok",	_("%) GPG key: %W%2%n"), 1);							/* sesja, klucz for /status */
	format_add("jabber_gpg_fail",	_("%> (%1) We didn't manage to sign testdata using key: %W%2%n (%R%3%n)\nOpenGPG support for this session disabled."), 1);	/* sesja, klucz, error */

/* stream:features */
	/* %1 - sesja, %2 - serwer, %3 - nazwa, %4 - XMLNS, %5 - z czym sie je */
	format_add("xmpp_feature_header",	_("%g,+=%G----- XMPP features %n(%T%2%n%3%n)"), 1);	/* %3 - todo */
	format_add("xmpp_feature",		_("%g|| %n %W%2%n can: %5 [%G%3%g,%4%n]"), 1);
	format_add("xmpp_feature_sub",		_("%g|| %n     %W%3%n: %5 [%G%4%n]"), 1);
	format_add("xmpp_feature_sub_unknown",	_("%g|| %n     %W%3%n: Unknown, report to devs [%G%4%n]"), 1);
	format_add("xmpp_feature_unknown",	_("%g|| %n %W%2%n feature: %r%3 %n[%G%3%g,%4%n]"), 1);
	format_add("xmpp_feature_footer",	_("%g`+=%G----- %n Turn it off using: /session display_server_features 0\n"), 1);

/* http://jabber.org/protocol/disco#items */
	/* %1 - session_name, %2 - uid (*_item: %3 - agent uid %4 - description %5 - seq id) */
	format_add("jabber_transport_list_begin",	_("%g,+=%G----- Available agents on: %T%2%n"), 1);
	format_add("jabber_transport_list_item",		("%g|| %n %6 - %W%3%n (%5)"), 1);
	format_add("jabber_transport_list_item_node",		_("%g|| %n %6 - %W%3%n node: %g%4%n (%5)"), 1);
	format_add("jabber_transport_list_end",		_("%g`+=%G----- End of the agents list%n\n"), 1);
	format_add("jabber_transport_list_nolist",	_("%! No agents @ %T%2%n"), 1);
	format_add("jabber_transport_error",		_("%! (%1) Error in getting %gavailable agents%n from %W%2%n: %r%3"), 1);

/* http://jabber.org/protocol/disco#items ## remotecontrol */
	format_add("jabber_remotecontrols_list_begin", _("%g,+=%G----- Available remote controls on: %T%2%n"), 1);
	format_add("jabber_remotecontrols_list_item",		("%g|| %n %6 - %W%4%n (%5)"), 1);		/* %3 - jid %4 - node %5 - descr %6 - seqid */
	format_add("jabber_remotecontrols_list_end",	_("%g`+=%G----- End of the remote controls list%n\n"), 1);
	format_add("jabber_remotecontrols_list_nolist", _("%! No remote controls @ %T%2%n"), 1);
	format_add("jabber_remotecontrols_error",	_("%! (%1) Error in getting %gavailable commands%n from %W%2%n: %r%3"), 1);

/* http://jabber.org/protocol/disco#info */
	format_add("jabber_transinfo_begin",		_("%g,+=%G----- Information about: %T%2%n"), 1);
	format_add("jabber_transinfo_begin_node",	_("%g,+=%G----- Information about: %T%2%n (%3)"), 1);
	format_add("jabber_transinfo_identify",			_("%g|| %G --== %g%3 %G==--%n"), 1);
		/* %4 - real fjuczer name  %3 - translated fjuczer name. */
	format_add("jabber_transinfo_feature",			_("%g|| %n %W%2%n feature: %n%3"), 1);
	format_add("jabber_transinfo_comm_ser",			_("%g|| %n %W%2%n can: %n%3 %2 (%4)"), 1);
	format_add("jabber_transinfo_comm_use",			_("%g|| %n %W%2%n can: %n%3 $uid (%4)"), 1);
	format_add("jabber_transinfo_comm_not",			_("%g|| %n %W%2%n can: %n%3 (%4)"), 1);
	format_add("jabber_transinfo_end",		_("%g`+=%G----- End of the infomations%n\n"), 1);
	format_add("jabber_transinfo_error",		_("%! (%1) Error in getting %ghttp://jabber.org/protocol/disco#info%n from %W%2%n: %r%3"), 1);

/* vCard xmlns='vcard-temp' */
	format_add("jabber_userinfo_response",		_("%> Jabber ID: %T%1%n\n%> Full Name: %T%2%n\n%> Nickname: %T%3%n\n%> Birthday: %T%4%n\n%> City: %T%5%n\n%> Desc: %T%6%n\n"), 1);

	format_add("jabber_userinfo_response2",		_("%g,+=%G----- vCard for:%n %T%2"), 1);
	format_add("jabber_userinfo_fullname",		_("%g|| %n   Full Name: %T%2"), 1);
	format_add("jabber_userinfo_nickname",		_("%g|| %n     Nickame: %T%2"), 1);
	format_add("jabber_userinfo_birthday",		_("%g|| %n    Birthday: %T%2"), 1);
	format_add("jabber_userinfo_email",		_("%g|| %n       Email: %T%2"), 1);
	format_add("jabber_userinfo_url",		_("%g|| %n     Webpage: %T%2"), 1);
	format_add("jabber_userinfo_desc",		_("%g|| %n Description: %T%2"), 1);
	format_add("jabber_userinfo_telephone",		_("%g|| %n   Telephone: %T%2"), 1);
	format_add("jabber_userinfo_title",		_("%g|| %n       Title: %T%2"), 1);
	format_add("jabber_userinfo_organization",	_("%g|| %nOrganization: %T%2"), 1);

	format_add("jabber_userinfo_adr",		_("%g|| ,+=%G----- (Next) %2 address"), 1);
	format_add("jabber_userinfo_adr_street",	_("%g|| || %n     Street: %T%2"), 1);
	format_add("jabber_userinfo_adr_postalcode",	_("%g|| || %nPostal code: %T%2"), 1);
	format_add("jabber_userinfo_adr_city",		_("%g|| || %n       City: %T%2"), 1);
	format_add("jabber_userinfo_adr_country",	_("%g|| || %n    Country: %T%2"), 1);
	format_add("jabber_userinfo_adr_end",		_("%g|| %g`+=%G-----"), 1);

	format_add("jabber_userinfo_photourl",		_("%g||\n%g|| %nYou can view attached photo at: %T%1"), 1);
	format_add("jabber_userinfo_end",		_("%g`+=%G-----"), 1);

	format_add("jabber_userinfo_error",		_("%! (%1) Error in getting %gvCard%n from %W%2%n: %r%3"), 1);

/* jabber:iq:privacy */
	/* %1 - session_name, %2 - server/ uid */
	format_add("jabber_privacy_list_begin",		_("%g,+=%G----- Privacy lists on %T%2%n"), 1);
	format_add("jabber_privacy_list_item",			_("%g|| %n %3 - %W%4%n"), 1);					/* %3 - lp %4 - itemname */
	format_add("jabber_privacy_list_item_def",		_("%g|| %g Default:%n %W%4%n"), 1);
	format_add("jabber_privacy_list_item_act",		_("%g|| %r  Active:%n %W%4%n"), 1);
	format_add("jabber_privacy_list_end",		_("%g`+=%G----- End of the privacy list%n"), 1);
	format_add("jabber_privacy_list_noitem",	_("%! No privacy lists in %T%2%n"), 1);
	format_add("jabber_privacy_item_header",	_("%g,+=%G----- Details for: %T%3%n\n%g||%n JID\t\t\t\t\t  MSG	PIN POUT IQ%n"), 1);
	format_add("jabber_privacy_item",			("%g||%n %[-44]4 \t%K|%n %[2]5 %K|%n %[2]6 %K|%n %[2]7 %K|%n %[2]8\n"), 1);
	format_add("jabber_privacy_item_footer",	_("%g`+=%G----- Legend: %n[%3] [%4]%n"), 1);
	/* %1 - item [group, jid, subscri*] */
	format_add("jabber_privacy_item_allow",		"%G%1%n", 1);
	format_add("jabber_privacy_item_deny",		"%R%1%n", 1);
	format_add("jabber_privacy_error",		_("%! (%1) Error in getting/setting %gprivacy list%n from %W%2%n: %r%3"), 1);

/* jabber:iq:private */
	/* %1 - session_name %2 - list_name %3 xmlns */
	format_add("jabber_private_list_header",	_("%g,+=%G----- Private list: %T%2/%3%n"), 1);
/* jabber:iq:private ## bookmarks */
	format_add("jabber_bookmark_url",			_("%g|| %n URL: %W%3%n (%2)"), 1);/* %1 - session_name, bookmark  url item: %2 - name %3 - url */
	format_add("jabber_bookmark_conf",			_("%g|| %n MUC: %W%3%n (%2)"), 1);/* %1 - session_name, bookmark conf item: %2 - name %3 - jid %4 - autojoin %5 - nick %6 - password */
/* jabber:iq:private ## config */
	format_add("jabber_private_list_item",			"%g|| %n %4: %W%5%n",  1);			/* %4 - item %5 - value */
	format_add("jabber_private_list_session",		"%g|| + %n Session: %W%4%n",  1);		/* %4 - uid */
	format_add("jabber_private_list_plugin",		"%g|| + %n Plugin: %W%4 (%5)%n",  1);	/* %4 - name %5 - prio*/
	format_add("jabber_private_list_subitem",		"%g||  - %n %4: %W%5%n",  1);		    /* %4 - item %5 - value */
	format_add("jabber_private_list_footer",	_("%g`+=%G----- End of the priv_data list%n"), 1);
	format_add("jabber_private_list_empty",		_("%! No list: %T%2/%3%n"), 1);
	format_add("jabber_private_list_error",		_("%! (%1) Error in request %gjabber:iq:private%n from %W%2%n: %r%3"), 1);

/* jabber:iq:search */
	format_add("jabber_search_item",	_("%) JID: %T%3%n\n%) Nickname:  %T%4%n\n%) Name: %T%5 %6%n\n%) Email: %T%7%n\n"), 1);	/* like gg-search_results_single */
		/* %3 - jid %4 - nickname %5 - firstname %6 - surname %7 - email */
	format_add("jabber_search_begin",	_("%g,+=%G----- Search on %T%2%n"), 1);
//	format_add("jabber_search_items",		("%g||%n %[-24]3 %K|%n %[10]5 %K|%n %[10]6 %K|%n %[12]4 %K|%n %[16]7"), 1);		/* like gg-search_results_multi. TODO */
	format_add("jabber_search_items",		("%g||%n %3 - %5 '%4' %6 <%7>"), 1);
	format_add("jabber_search_end",		_("%g`+=%G-----"), 1);
	format_add("jabber_search_error",	_("%! (%1) Error in %gjabber:iq:search%n from %W%2%n: %r%3"), 1);

/* jabber:iq:last */
	format_add("jabber_lastseen_response",		_("%> Jabber ID:  %T%1%n\n%> Logged out: %T%2 ago%n\n"), 1);
	format_add("jabber_lastseen_uptime",		_("%> Jabber ID: %T%1%n\n%> Server up: %T%2 ago%n\n"), 1);
	format_add("jabber_lastseen_idle",		_("%> Jabber ID: %T%1%n\n%> Idle for:  %T%2%n\n"), 1);
	format_add("jabber_lastseen_error",		_("%! (%1) Error in getting %gjabber:iq:last%n from %W%2%n: %r%3"), 1);

/* jabber:iq:version */
	format_add("jabber_version_response",		_("%> Jabber ID: %T%1%n\n%> Client name: %T%2%n\n%> Client version: %T%3%n\n%> Operating system: %T%4%n\n"), 1);
	format_add("jabber_version_error",		_("%! (%1) Error in getting %gjabber:iq:version%n from %W%2%n: %r%3"), 1);

	format_add("jabber_ctcp_request",		_("%> (%1) %T%2%n requested IQ %g%4%n"), 1);

#endif	/* !NO_DEFAULT_THEME */
	return 0;
}

void jabber_gpg_changed(session_t *s, const char *name) {
	plugin_t *gpg_plug;
	const char *key;
	const char *passhrase;

	char *error;
	char *msg;

	if (!session_postinit) return;

/* SLOWDOWN! */
	session_int_set(s, "__gpg_enabled", 0);
	if (session_int_get(s, "gpg_active") != 1) return;

	if (!(key = session_get(s, "gpg_key")) || !(passhrase = session_get(s, "gpg_password"))) {
		print("jabber_gpg_config", session_name(s));
		return;
	}

	if (!(gpg_plug = plugin_find("gpg"))) {
		print("jabber_gpg_plugin", session_name(s));
		return;		/* don't remove prev set password... */
	}

	msg = xstrdup("test");
	msg = jabber_openpgp(s, NULL, JABBER_OPENGPG_SIGN, msg, NULL, &error);

	if (error) {
		session_set(s, "gpg_active", "0");
		session_set(s, "gpg_password", NULL);
		print("jabber_gpg_fail", session_name(s), key, error);
		xfree(error);
	} else	{
		session_int_set(s, "__gpg_enabled", 1);
		print("jabber_gpg_ok", session_name(s), key);
	}
	jabber_write_status(s);
	xfree(msg);
}

static void jabber_statusdescr_handler(session_t *s, const char *name) {
	jabber_write_status(s);
}

/**
 * jabber_pgp_postinit()
 *
 * Handler for: <i>CONFIG_POSTINIT</i><br>
 * Executed after ekg2 read sessions configuration.<br>
 * Here we try to init gpg for <b>all</b> jabber sessions by calling jabber_gpg_changed()<br>
 *
 * @return 0
 */

static QUERY(jabber_pgp_postinit) {
	session_t *s;

	session_postinit = 1;

	for (s = sessions; s; s = s->next) {
		/* check if it's jabber_plugin session [DON'T DO IT ON TLEN SESSIONS] */
		if (s && s->plugin == &jabber_plugin && !jabber_private(s)->istlen)
			jabber_gpg_changed(s, NULL);
	}
	return 0;
}

static QUERY(jabber_userlist_info) {
	userlist_t *u	= *va_arg(ap, userlist_t **);
	int quiet	= *va_arg(ap, int *);
	jabber_userlist_private_t *up;

	if (!u || valid_plugin_uid(&jabber_plugin, u->uid) != 1 || !(up = jabber_userlist_priv_get(u)))
		return 1;

	printq("user_info_auth_type", jabber_authtypes[up->authtype & EKG_JABBER_AUTH_BOTH]);

	return 0;
}

static QUERY(jabber_userlist_priv_handler) {
	userlist_t *u	= *va_arg(ap, userlist_t **);
	int function	= *va_arg(ap, int *);
	jabber_userlist_private_t *j;

	if (!u || (valid_plugin_uid(&jabber_plugin, u->uid) != 1))
		return 1;

	if (!(j = u->priv)) {
		if (function == EKG_USERLIST_PRIVHANDLER_FREE)
			return -1;

		j = xmalloc(sizeof(jabber_userlist_private_t));
		u->priv = j;
	}

	switch (function) {
		case EKG_USERLIST_PRIVHANDLER_FREE:
			xfree(j->role);
			xfree(j->aff);
			xfree(u->priv);
			u->priv = NULL;
			break;

		case EKG_USERLIST_PRIVHANDLER_GET:
			*va_arg(ap, void **) = j;
			break;

		default:
			return 2;
	}
	return -1;
}

static QUERY(jabber_typing_out) {
	const char *session	= *va_arg(ap, const char **);
	const char *uid		= *va_arg(ap, const char **);
	int chatstate		= *va_arg(ap, const int *);

	const char *jid		= uid + 5;
	session_t *s		= session_find(session);
	jabber_private_t *j;

	if (!s || s->plugin != &jabber_plugin)
		return 0;

	/* if user closes window while typing,
	 * and we are prohibited to send <gone/>,
	 * we just send standard <active/> */
	if ((EKG_CHATSTATE_GONE==chatstate) && (config_jabber_disable_chatstates & EKG_CHATSTATE_GONE))
		chatstate = EKG_CHATSTATE_ACTIVE;
	else if (config_jabber_disable_chatstates & chatstate)
		return -1;

	j = jabber_private(s);

	if (j->istlen) {
		if (!(chatstate & EKG_CHATSTATE_COMPOSING))
			return -1;
		jabber_write(s, "<m to='%s' tp='%c'/>",
			jid, (chatstate==EKG_CHATSTATE_COMPOSING ? 't' : 'u'));
		return 0;
	}

	if (!newconference_find(s, uid) /* DON'T SEND CHATSTATES TO MUCS! */) {
		int len = 0;
		char *csname;
		switch (chatstate) {
			case EKG_CHATSTATE_COMPOSING:	csname = "composing"; len = 1; break;
			case EKG_CHATSTATE_ACTIVE:	csname = "active"; break;
			case EKG_CHATSTATE_GONE:	csname = "gone"; break;
			case EKG_CHATSTATE_PAUSED:	csname = "paused"; break;
			case EKG_CHATSTATE_INACTIVE:	csname = "inactive"; break;
			default: return -1;
		}

		jabber_write(s, "<message type='chat' to='%s'>"
			"<x xmlns='jabber:x:event'%s>"
			"<%s xmlns='http://jabber.org/protocol/chatstates'/>"
			"</message>\n", jid, (len ? "><composing/></x" : "/"), csname);
	}

	return 0;
}

	/* KEEP IT SORTED, MEN! */
static plugins_params_t jabber_plugin_vars[] = {
	PLUGIN_VAR_ADD("alias",			VAR_STR, 0, 0, NULL),
	PLUGIN_VAR_ADD("allow_add_reply_id",	VAR_INT, "1", 0, NULL),
	/* '666' enabled for everyone (DON'T TRY IT!); '0' - disabled; '1' - enabled for the same id (allow from diffrent resources); '2' - enabled for allow_remote_control_jids (XXX) */
	PLUGIN_VAR_ADD("allow_remote_control",	VAR_INT, "0", 0, NULL),
	PLUGIN_VAR_ADD("auto_auth",		VAR_INT, "0", 0, NULL),
	PLUGIN_VAR_ADD("auto_away",		VAR_INT, "0", 0, NULL),
	PLUGIN_VAR_ADD("auto_away_descr",	VAR_STR, 0, 0, NULL),
	PLUGIN_VAR_ADD("auto_back",		VAR_INT, "0", 0, NULL),
	PLUGIN_VAR_ADD("auto_bookmark_sync",	VAR_BOOL, "0", 0, NULL),
	PLUGIN_VAR_ADD("auto_connect",		VAR_INT, "0", 0, NULL),
	PLUGIN_VAR_ADD("auto_find",		VAR_INT, "0", 0, NULL),
	PLUGIN_VAR_ADD("auto_privacylist_sync", VAR_BOOL, "0", 0, NULL),
	PLUGIN_VAR_ADD("auto_reconnect",	VAR_INT, "0", 0, NULL),
	PLUGIN_VAR_ADD("auto_xa",		VAR_INT, "0", 0, NULL),
	PLUGIN_VAR_ADD("auto_xa_descr",		VAR_STR, 0, 0, NULL),
	PLUGIN_VAR_ADD("connect_timeout",	VAR_INT, "30", 0, NULL),
	PLUGIN_VAR_ADD("display_ctcp",		VAR_BOOL, "0", 0, NULL),
	PLUGIN_VAR_ADD("display_notify",	VAR_INT, "-1", 0, NULL),
	PLUGIN_VAR_ADD("display_server_features", VAR_INT, "1", 0, NULL),
	PLUGIN_VAR_ADD("gpg_active",		VAR_BOOL, "0", 0, jabber_gpg_changed),
	PLUGIN_VAR_ADD("gpg_key",		VAR_STR, NULL, 0, jabber_gpg_changed),
	PLUGIN_VAR_ADD("gpg_password",		VAR_STR, NULL, 1, jabber_gpg_changed),
	PLUGIN_VAR_ADD("log_formats",		VAR_STR, "xml,simple,sqlite", 0, NULL),
	PLUGIN_VAR_ADD("msg_gen_thread",	VAR_BOOL, "0", 0, NULL),
	PLUGIN_VAR_ADD("password",		VAR_STR, NULL, 1, NULL),
	PLUGIN_VAR_ADD("photo_hash",		VAR_STR, NULL, 0, NULL),
	PLUGIN_VAR_ADD("plaintext_passwd",	VAR_INT, "0", 0, NULL),
	PLUGIN_VAR_ADD("ping_server",		VAR_BOOL, "0", 0, NULL),
	PLUGIN_VAR_ADD("port",			VAR_INT, "5222", 0, NULL),
	PLUGIN_VAR_ADD("prefer_family",		VAR_INT, "0", 0, NULL),
	PLUGIN_VAR_ADD("priority",		VAR_INT, "5", 0, NULL),
	PLUGIN_VAR_ADD("privacy_list",		VAR_STR, 0, 0, NULL),
	PLUGIN_VAR_ADD("resource",		VAR_STR, 0, 0, NULL),
	PLUGIN_VAR_ADD("server",		VAR_STR, 0, 0, NULL),
	PLUGIN_VAR_ADD("ssl_port",		VAR_INT, "5223", 0, NULL),
	PLUGIN_VAR_ADD("statusdescr",		VAR_STR, 0, 0, jabber_statusdescr_handler),
	PLUGIN_VAR_ADD("use_compression",	VAR_STR, 0, 0, NULL),		/* for instance: zlib,lzw */
	PLUGIN_VAR_ADD("use_ssl",		VAR_BOOL, "0", 0, NULL),
	PLUGIN_VAR_ADD("use_tls",		VAR_BOOL, "1", 0, NULL),
	PLUGIN_VAR_ADD("ver_client_name",	VAR_STR, 0, 0, NULL),
	PLUGIN_VAR_ADD("ver_client_version",	VAR_STR, 0, 0, NULL),
	PLUGIN_VAR_ADD("ver_os",		VAR_STR, 0, 0, NULL),

	PLUGIN_VAR_END()
};

/**
 * jabber_plugin_init()
 *
 * Register jabber plugin, assign plugin params [jabber_plugin_vars], connect to most important events<br>
 * register global jabber variables, register commands with call to jabber_register_commands()<br>
 *
 * @todo We should set default global jabber variables with set-vars-default
 *
 * @sa jabber_plugin_destroy()
 *
 * @return 0 [successfully loaded plugin]
 */

static const char *jabber_protocols[]	= { "xmpp:", "tlen:", NULL };
static const status_t jabber_statuses[]	= {
	EKG_STATUS_NA, EKG_STATUS_DND, EKG_STATUS_XA, EKG_STATUS_AWAY, EKG_STATUS_AVAIL, EKG_STATUS_FFC,
	EKG_STATUS_INVISIBLE, EKG_STATUS_ERROR, EKG_STATUS_UNKNOWN, EKG_STATUS_NULL
};

static const struct protocol_plugin_priv jabber_priv = {
	.protocols	= jabber_protocols,
	.statuses	= jabber_statuses
};

EXPORT int jabber_plugin_init(int prio) {

	PLUGIN_CHECK_VER("jabber");

	jabber_plugin.params	= jabber_plugin_vars;
	jabber_plugin.priv		= &jabber_priv;

	plugin_register(&jabber_plugin, prio);

	session_postinit = 0;

	query_connect(&jabber_plugin, "protocol-validate-uid",	jabber_validate_uid, NULL);
	query_connect(&jabber_plugin, "plugin-print-version",	jabber_print_version, NULL);
	query_connect(&jabber_plugin, "session-added",		jabber_session_init, NULL);
	query_connect(&jabber_plugin, "session-removed",	jabber_session_deinit, NULL);
	query_connect(&jabber_plugin, "status-show",		jabber_status_show_handle, NULL);
	query_connect(&jabber_plugin, "ui-window-kill",	jabber_window_kill, NULL);
	query_connect(&jabber_plugin, "protocol-ignore",	jabber_protocol_ignore, NULL);
	query_connect(&jabber_plugin, "config-postinit",	jabber_dcc_postinit, NULL);
	query_connect(&jabber_plugin, "config-postinit",	jabber_pgp_postinit, NULL);
	query_connect(&jabber_plugin, "userlist-info",		jabber_userlist_info, NULL);
	query_connect(&jabber_plugin, "userlist-privhandle",	jabber_userlist_priv_handler, NULL);
	query_connect(&jabber_plugin, "protocol-typing-out",	jabber_typing_out, NULL);

	variable_add(&jabber_plugin, ("xmpp:beep_mail"), VAR_BOOL, 1, &config_jabber_beep_mail, NULL, NULL, NULL);
	variable_add(&jabber_plugin, ("xmpp:dcc"), VAR_BOOL, 1, &jabber_dcc, (void*) jabber_dcc_postinit, NULL, NULL);
	variable_add(&jabber_plugin, ("xmpp:dcc_ip"), VAR_STR, 1, &jabber_dcc_ip, NULL, NULL, NULL);
	variable_add(&jabber_plugin, ("xmpp:default_pubsub_server"), VAR_STR, 1, &jabber_default_pubsub_server, NULL, NULL, NULL);
	variable_add(&jabber_plugin, ("xmpp:default_search_server"), VAR_STR, 1, &jabber_default_search_server, NULL, NULL, NULL);
	variable_add(&jabber_plugin, ("xmpp:disable_chatstates"), VAR_MAP, 1, &config_jabber_disable_chatstates, NULL,
			variable_map(4, 0, 0, "none",
					EKG_CHATSTATE_COMPOSING, 0, "composing",
					EKG_CHATSTATE_ACTIVE, 0, "active",
					EKG_CHATSTATE_GONE, 0, "gone"), NULL);

	jabber_register_commands();

	return 0;
}

/**
 * jabber_plugin_destroy()
 *
 * Unregister jabber plugin.
 *
 * @sa jabber_plugin_init()
 *
 * @return 0 [successfully unloaded plugin]
 */

static int jabber_plugin_destroy() {

	plugin_unregister(&jabber_plugin);

	return 0;
}

/*
 * Local Variables:
 * mode: c
 * c-file-style: "k&r"
 * c-basic-offset: 8
 * indent-tabs-mode: t
 * End:
 * vim: noet
 */
