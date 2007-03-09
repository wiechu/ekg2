/* $Id$ */

/*
 *  (C) Copyright 2003-2005 Wojtek Kaniewski <wojtekka@irc.pl>
 *                          Tomasz Torcz <zdzichu@irc.pl>
 *                          Leszek Krupiński <leafnode@pld-linux.org>
 *                          Piotr Pawłow and other libtlen developers (http://libtlen.sourceforge.net/index.php?theme=teary&page=authors)
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

#include "ekg2-config.h"
#include <ekg/win32.h>

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

#ifdef __sun      /* Solaris, thanks to Beeth */
#include <sys/filio.h>
#endif

#ifdef HAVE_ZLIB
# include "zlib.h"
#endif

#include <ekg/debug.h>
#include <ekg/dynstuff.h>
#include <ekg/protocol.h>
#include <ekg/sessions.h>
#include <ekg/stuff.h>
#include <ekg/userlist.h>
#include <ekg/themes.h>
#include <ekg/vars.h>
#include <ekg/xmalloc.h>
#include <ekg/log.h>

#include <ekg/queries.h>

#include "jabber.h"
#include "jabber-ssl.h"
#include "jabber_dcc.h"

#ifdef JABBER_HAVE_OPENSSL
SSL_CTX *jabberSslCtx;
#endif

char *jabber_default_search_server = NULL;
char *jabber_default_pubsub_server = NULL;
int config_jabber_beep_mail = 0;

static int session_postinit;
static int jabber_theme_init();
static WATCHER(jabber_handle_connect_ssl);
PLUGIN_DEFINE(jabber, PLUGIN_PROTOCOL, jabber_theme_init);

#ifdef EKG2_WIN32_SHARED_LIB
	EKG2_WIN32_SHARED_LIB_HELPER
#endif

/*
 * jabber_private_destroy()
 *
 * inicjuje jabber_private_t danej sesji.
 */
static void jabber_private_init(session_t *s) {
        jabber_private_t *j;

	if (!s || s->priv || s->plugin != &jabber_plugin)
		return;

        s->priv = j = xmalloc(sizeof(jabber_private_t));
        j->fd = -1;
	j->istlen = !xstrncasecmp(s->uid, "tlen:", 5);
}

/*
 * jabber_private_destroy()
 *
 * zwalnia jabber_private_t danej sesji.
 */
static void jabber_private_destroy(session_t *s) {
        jabber_private_t *j;

	if (!s || !(j = s->priv) || s->plugin != &jabber_plugin)
		return;

        xfree(j->server);
	xfree(j->resource);
	xfree(j->last_gmail_result_time);
	xfree(j->last_gmail_tid);

        if (j->parser)
                XML_ParserFree(j->parser);
	jabber_bookmarks_free(j);
	jabber_privacy_free(j);

        xfree(j);
	s->priv = NULL;
}

/* destroy all previously saved jabber:iq:privacy list... we DON'T DELETE LIST on jabberd server... only list saved @ j->privacy */

int jabber_privacy_free(jabber_private_t *j) {
	list_t l;
	if (!j || !j->privacy) return -1;

	for (l = j->privacy; l; l = l->next) {
		jabber_iq_privacy_t *pr = l->data;
		if (!pr) continue;

		xfree(pr->type);
		xfree(pr->value);

		xfree(pr);
		l->data = NULL;
	}
	list_destroy(j->privacy, 0);
	j->privacy = NULL;
	return 0;
}

/* destory all previously saved bookmarks... we DON'T DELETE LIST on jabberd server... only list saved @ j->bookamarks */
int jabber_bookmarks_free(jabber_private_t *j) {
	list_t l;
	if (!j || !j->bookmarks) return -1;

	for (l = j->bookmarks; l; l = l->next) {
		jabber_bookmark_t *book = l->data;
		if (!book) continue;

		if (book->type == JABBER_BOOKMARK_URL) { xfree(book->private.url->name); xfree(book->private.url->url); }
		else if (book->type == JABBER_BOOKMARK_CONFERENCE) { 
			xfree(book->private.conf->name); xfree(book->private.conf->jid);
			xfree(book->private.conf->nick); xfree(book->private.conf->pass);
		}
		xfree(book->private.other);
		xfree(book);
		l->data = NULL;
	}
	list_destroy(j->bookmarks, 0); 
	j->bookmarks = NULL;
	return 0;
}

/*
 * jabber_session()
 *
 * obsługuje dodawanie i usuwanie sesji -- inicjalizuje lub zwalnia
 * strukturę odpowiedzialną za wnętrzności jabberowej sesji.
 */
static QUERY(jabber_session) {
        char **session = va_arg(ap, char**);
        session_t *s = session_find(*session);

        if (!s)
                return -1;

        if (data)
                jabber_private_init(s);
        else
                jabber_private_destroy(s);

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
 * handler for: <i>PROTOCOL_VALIDATE_UID</i>
 * checks, if @a uid is <i>proper for jabber plugin</i>.
 *
 * @note <i>Proper for jabber plugin</i> means either:
 * 	- If @a uid starts with jid: have got '@' (but jid:@ is wrong) and after '@' there is at least one char	[<b>xmpp protocol</b>]<br>
 * 	- If @a uid starts with tlen: (and len > 5)								[<b>tlen protocol</b>]
 *
 * @param ap 1st param: <i>(char *) </i><b>uid</b>  - of user/session/command/whatever
 * @param ap 2nd param: <i>(int) </i><b>valid</b> - place to put 1 if uid is valid for jabber plugin.
 * @param data NULL
 *
 * @return 	-1 if it's valid uid for jabber plugin<br>
 * 		 0 if not
 */

static QUERY(jabber_validate_uid) {
	char *uid = *(va_arg(ap, char **));
	int *valid = va_arg(ap, int *);
	const char *m;

	if (!uid)
		return 0;

	/* minimum: jid:a@b */
	if (!xstrncasecmp(uid, "jid:", 4) && (m=xstrchr(uid+4, '@')) && ((uid+4)<m) && m[1] != '\0') {
		(*valid)++;
		return -1;
	}

	if (!xstrncasecmp(uid, "tlen:", 5) && uid[5] != '\0') {
		(*valid)++;
		return -1;
	}

	return 0;
}

/**
 * jabber_protocols()
 *
 * Handler for: <i>GET_PLUGIN_PROTOCOLS</i><br>
 * It just add "tlen:" and "jid:" to @a arr
 *
 * @note I know it's nowhere used. It'll be used by d-bus plugin.
 *
 * @todo Instead of "jid:" add "xmpp:" ?
 *
 * @param ap 1st param: <i>(char **) </i><b>arr</b> - array with available protocols
 * @param data NULL
 *
 * @return 0
 */

static QUERY(jabber_protocols) {
	char ***arr = va_arg(ap, char ***);

	array_add(arr, "tlen:");
	array_add(arr, "jid:");
	return 0;
}

static QUERY(jabber_window_kill) {
	window_t        *w = *va_arg(ap, window_t **);
	jabber_private_t *j;
	newconference_t  *c;

	char *status = NULL;

	if (w && w->id && w->target && session_check(w->session, 1, "jid") && (c = newconference_find(w->session, w->target)) &&
			(j = jabber_private(w->session)) && session_connected_get(w->session)) {
		watch_write(j->send_watch, "<presence to=\"%s/%s\" type=\"unavailable\">%s</presence>", w->target+4, c->private, status ? status : "");
		newconference_destroy(c, 0);
	}

	return 0;
}

int jabber_write_status(session_t *s)
{
	jabber_private_t *j = session_private_get(s);
	int prio = session_int_get(s, "priority");
	int status;
	char *descr;
	char *real = NULL;
	char *priority = NULL;
	char *x_signed = NULL;

#if WITH_JABBER_JINGLE
/* This is only to enable 'call' button in GTalk .... */
# define JINGLE_CAPS "<c xmlns=\"http://jabber.org/protocol/caps\" ext=\"voice-v1\" ver=\"0.1\" node=\"http://www.google.com/xmpp/client/caps\"/>"
#else 
# define JINGLE_CAPS ""
#endif

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
		priority = saprintf("<priority>%d</priority>", prio); /* priority only in real jabber session */

		if (session_int_get(s, "__gpg_enabled") == 1) {
			char *signpresence;
			
			signpresence = xstrdup(session_descr_get(s));	/* XXX, data in unicode required (?) */
			if (!signpresence) 
				signpresence = xstrdup("");

			signpresence = jabber_openpgp(s, NULL, JABBER_OPENGPG_SIGN, signpresence, NULL, NULL);
			if (signpresence) {
				x_signed = saprintf("<x xmlns=\"jabber:x:signed\">%s</x>", signpresence);
				xfree(signpresence);
			}
		}
	}
#define P(x) (x ? x : "")
	if (!j->istlen && (status == EKG_STATUS_AVAIL))
		watch_write(j->send_watch, "<presence>%s%s%s%s</presence>", P(real), P(priority), P(x_signed), JINGLE_CAPS);
	else if (status == EKG_STATUS_INVISIBLE)
		watch_write(j->send_watch, "<presence type=\"invisible\">%s%s</presence>", P(real), P(priority));
	else {
		const char *status_s;

		if (j->istlen && (status == EKG_STATUS_AVAIL)) status_s = "available";
		else status_s = ekg_status_string(status, 0);
		watch_write(j->send_watch, "<presence><show>%s</show>%s%s%s%s</presence>", status_s, P(real), P(priority), P(x_signed), JINGLE_CAPS);
	}
#undef P

	xfree(priority);
	xfree(real);
	xfree(x_signed);
	return 0;
}

void jabber_handle_disconnect(session_t *s, const char *reason, int type)
{
        jabber_private_t *j = jabber_private(s);

        if (!j)
                return;

        session_connected_set(s, 0);
        j->connecting = 0;

	if (j->send_watch) {
		j->send_watch->type = WATCH_NONE;
		watch_free(j->send_watch);
		j->send_watch = NULL;
	}

	if (j->connecting)
		watch_remove(&jabber_plugin, j->fd, WATCH_WRITE);
	watch_remove(&jabber_plugin, j->fd, WATCH_READ);

	j->using_compress = JABBER_COMPRESSION_NONE;
#ifdef JABBER_HAVE_SSL
        if (j->using_ssl && j->ssl_session)
		SSL_BYE(j->ssl_session);
#endif
        close(j->fd);
        j->fd = -1;

#ifdef JABBER_HAVE_SSL
        if (j->using_ssl && j->ssl_session)
                SSL_DEINIT(j->ssl_session);
	j->using_ssl	= 0;
	j->ssl_session	= NULL;
#endif

        if (j->parser)
                XML_ParserFree(j->parser);
        j->parser = NULL;
	session_set(s, "__sasl_excepted", NULL);

	{
		char *__session = xstrdup(session_uid_get(s));
		char *__reason = xstrdup(reason);
		
		query_emit_id(NULL, PROTOCOL_DISCONNECTED, &__session, &__reason, &type, NULL);

		xfree(__session);
		xfree(__reason);
	}
}

static void jabber_handle_start(void *data, const char *name, const char **atts)
{
        jabber_handler_data_t *jdh = (jabber_handler_data_t*) data;
        jabber_private_t *j = session_private_get(jdh->session);
        session_t *s = jdh->session;

        if (!session_connected_get(s) && ((j->istlen && !xstrcmp(name, "s")) || (!j->istlen && !xstrcmp(name, "stream:stream")))) {
		char *passwd		= (char*) session_get(s, "password");
		char *resource		= jabber_escape(session_get(s, "resource"));
		char *epasswd		= NULL;

                char *username;
		char *authpass;
		char *stream_id;
		if (!j->istlen) username = xstrdup(s->uid + 4);
		else 		username = xstrdup(s->uid + 5);
		*(xstrchr(username, '@')) = 0;
	
		if (!j->istlen && session_get(s, "__new_acount")) {
			epasswd		= jabber_escape(passwd);
			watch_write(j->send_watch, 
				"<iq type=\"set\" to=\"%s\" id=\"register%d\">"
				"<query xmlns=\"jabber:iq:register\"><username>%s</username><password>%s</password></query></iq>", 
				j->server, j->id++, username, epasswd ? epasswd : ("foo"));
		}

                if (!resource)
                        resource = xstrdup(JABBER_DEFAULT_RESOURCE);

		xfree(j->resource);
		j->resource = resource;

		if (!j->istlen && session_int_get(s, "use_sasl") == 1) {
			xfree(username);	/* waste */
			return;
		}

		/* stolen from libtlen function calc_passcode() Copyrighted by libtlen's developer and Piotr Pawłow */
		if (j->istlen) {
			int     magic1 = 0x50305735, magic2 = 0x12345671, sum = 7;
			char    z;
			while ((z = *passwd++) != 0) {
				if (z == ' ' || z == '\t') continue;
				magic1 ^= (((magic1 & 0x3f) + sum) * z) + (magic1 << 8);
				magic2 += (magic2 << 8) ^ magic1;
				sum += z;
			}
			magic1 &= 0x7fffffff;
			magic2 &= 0x7fffffff;

			epasswd = passwd = saprintf("%08x%08x", magic1, magic2);
		} else if (session_int_get(s, "plaintext_passwd") && !epasswd) {
			epasswd = jabber_escape(passwd);
		}

		stream_id = jabber_attr((char **) atts, 
					j->istlen ? "i" : "id");

		authpass = (!j->istlen && session_int_get(s, "plaintext_passwd")) ? 
			saprintf("<password>%s</password>", epasswd) :			/* plaintext */
			saprintf("<digest>%s</digest>", jabber_digest(stream_id, passwd));	/* hash */

		watch_write(j->send_watch, 
			"<iq type=\"set\" id=\"auth\" to=\"%s\"><query xmlns=\"jabber:iq:auth\"><username>%s</username>%s<resource>%s</resource></query></iq>", 
			j->server, username, authpass, resource);
                xfree(username);
		xfree(authpass);

		xfree(epasswd);
	} else
		xmlnode_handle_start(data, name, atts);
}

static WATCHER(jabber_handle_stream)
{
        jabber_handler_data_t *jdh	= (jabber_handler_data_t *) data;
        session_t *s			= (session_t *) jdh->session;
        jabber_private_t *j		= session_private_get(s);
	XML_Parser parser;				/* j->parser */
	char *uncompressed	= NULL;
        char *buf;
        int len;
	int rlen;

        s->activity = time(NULL);

        /* ojej, rozłączyło nas */
        if (type == 1) {
                debug("[jabber] jabber_handle_stream() type == 1, exitting\n");

		if (s && session_connected_get(s))  /* hack to avoid reconnecting when we do /disconnect */
			jabber_handle_disconnect(s, NULL, EKG_DISCONNECT_NETWORK);

		xfree(data);
                return 0;
        }

	debug_function("[jabber] jabber_handle_stream()\n");
	parser = j->parser;

        if (!(buf = XML_GetBuffer(parser, 4096))) {
		jabber_handle_disconnect(s, "XML_GetBuffer failed", EKG_DISCONNECT_FAILURE);
                return -1;
        }
#ifdef JABBER_HAVE_SSL
        if (j->using_ssl && j->ssl_session) {

		len = SSL_RECV(j->ssl_session, buf, 4095);
#ifdef JABBER_HAVE_OPENSSL
		if ((len == 0 && SSL_get_error(j->ssl_session, len) == SSL_ERROR_ZERO_RETURN)); /* connection shut down cleanly */
		else if (len < 0) 
			len = SSL_get_error(j->ssl_session, len);
/* XXX, When an SSL_read() operation has to be repeated because of SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE, it must be repeated with the same arguments. */
#endif

		if (SSL_E_AGAIN(len)) {
			// will be called again
			ekg_yield_cpu();
			return 0;
		}

                if (len < 0) {
			jabber_handle_disconnect(s, SSL_ERROR(len), EKG_DISCONNECT_FAILURE);
                        return -1;
                }
        } else
#endif
#ifdef NO_POSIX_SYSTEM
                if ((len = recv(fd, buf, 4095, 0)) < 1) {
#else
                if ((len = read(fd, buf, 4095)) < 1) {
#endif
			if (len == -1 && (errno == EINPROGRESS || errno == EAGAIN)) return 0;
			jabber_handle_disconnect(s, len == -1 ? strerror(errno) : "got disconnected", len == -1 ? EKG_DISCONNECT_FAILURE : EKG_DISCONNECT_NETWORK);
                        return -1;
                }

        buf[len] = 0;
	rlen = len;

	switch (j->using_compress) {
		case JABBER_COMPRESSION_ZLIB:
#ifdef HAVE_ZLIB
			uncompressed = jabber_zlib_decompress(buf, &rlen);
#else
			debug_error("[jabber] jabber_handle_stream() compression zlib, but no zlib support.. you're joking, right?\n");
#endif
			break;

		case JABBER_COMPRESSION_LZW:
			debug_error("[jabber] jabber_handle_stream() j->using_compress XXX implement LZW!\n");
			break;

		case JABBER_COMPRESSION_NONE:
		case JABBER_COMPRESSION_LZW_INIT:
		case JABBER_COMPRESSION_ZLIB_INIT:
			break;

		default:
			debug_error("[jabber] jabber_handle_stream() j->using_compress wtf? unknown! %d\n", j->using_compress);
	}

	debug_iorecv("[jabber] (%db/%db) recv: %s\n", rlen, len, uncompressed ? uncompressed : buf);
/*
	if (uncompressed) {
		memcpy(buf, uncompressed, rlen);
	}
 */

	if (!XML_ParseBuffer(parser, rlen, (rlen == 0))) 
//	if (!XML_Parse(parser, uncompressed ? uncompressed : buf, rlen, (rlen == 0))) 
	{
		print("jabber_xmlerror", session_name(s));
		debug_error("jabber_xmlerror: %s\n", XML_ErrorString(XML_GetErrorCode(parser)));

		if ((!j->parser && parser) || (parser != j->parser)) XML_ParserFree(parser);
		xfree(uncompressed);
		return -1;
	}
	if ((!j->parser && parser) || (parser != j->parser)) XML_ParserFree(parser);
	xfree(uncompressed);

	return 0;
}

static TIMER(jabber_ping_timer_handler) {
	session_t *s = session_find((char*) data);

	if (type == 1) {
		xfree(data);
		return 0;
	}

	if (!s || !s->priv || !s->connected) {
		return -1;
	}

	if (jabber_private(s)->istlen) {
		jabber_write(s, "  \t  ");	/* ping according to libtlen */
		return 0;
	}
	
	if (session_int_get(s, "ping-server") == 0) return -1;

	jabber_write(s, "<iq/>"); /* leafnode idea */
	return 0;
}

static WATCHER(jabber_handle_connect_tlen_hub) {	/* tymczasowy */
	session_t *s = (session_t *) data;
	if (type) return 0;
	debug_error("Connecting to HUB, currectly not works ;/");
	jabber_handle_disconnect(s, "Unimplemented do: /eval \"/session server s1.tlen.pl\" \"/session port 443\" \"/connect\" sorry.", EKG_DISCONNECT_FAILURE);
	return -1;

#if 0
	if (type) {
		close(fd);
		if (type == 2) debug("TIMEOUT\n");
		return 0;
	}
	
	if ((int) watch == WATCH_WRITE) {
		char *req, *esc; 
		int res = 0, res_size = sizeof(res);
		if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &res, &res_size) || res) {
			jabber_handle_disconnect(s, strerror(res), EKG_DISCONNECT_FAILURE);
			return -1;
		}
		esc = tlen_encode(s->uid+4);
		req = saprintf("GET /4starters.php?u=%s&v=10 HTTP/1.0\r\nHost: %s\r\n\r\n", esc, TLEN_HUB);	/* libtlen */
		write(fd, req, xstrlen(req));
		xfree(req);
		xfree(esc);

		/* XXX, timeout? */
		watch_add(&jabber_plugin, fd, WATCH_READ, jabber_handle_connect_tlen_hub, data);	/* WATCH_READ_LINE? */
		return -1;
	} else if ((int) watch == WATCH_READ) {	/* libtlen */
		char *header, *body;
		char buf[1024];
		int len;

		len = read(fd, buf, sizeof(buf));
		buf[len] = 0;

		header	= xstrstr(buf, "\r\n");
		body	= xstrstr(buf, "\r\n\r\n");
		if (header && body) {
			xmlnode_t *rv;

			*header = '\0';
			body += 4;
			if (xstrstr(buf, " 200 ")) {
				debug_function("[TLEN, HUB]: %s\n", body);
				return -1;
			}
		} else debug_error("[TLEN, HUB]: FAILED\n");

		if (len == 0)	return -1;
		else		return 0;
	} else return -1;
#endif
}

XML_Parser jabber_parser_recreate(XML_Parser parser, void *data) {
/*	debug_function("jabber_parser_recreate() 0x%x 0x%x\n", parser, data); */

	if (!parser) 	parser = XML_ParserCreate("UTF-8");	/*   new parser */
	else		XML_ParserReset(parser, "UTF-8");	/* reset parser */

	XML_SetUserData(parser, (void*) data);
	XML_SetElementHandler(parser, (XML_StartElementHandler) jabber_handle_start, (XML_EndElementHandler) xmlnode_handle_end);
	XML_SetCharacterDataHandler(parser, (XML_CharacterDataHandler) xmlnode_handle_cdata);

	return parser;
}

static WATCHER(jabber_handle_connect) /* tymczasowy */
{
	session_t *s = (session_t *) data;
        jabber_private_t *j = session_private_get(s);
       	jabber_handler_data_t *jdh;

        int res = 0;
	socklen_t res_size = sizeof(res);
	char *tname;

        debug_function("[jabber] jabber_handle_connect()\n");

        if (type) {
                return 0;
        }

        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &res, &res_size) || res) {
                jabber_handle_disconnect(s, strerror(res), EKG_DISCONNECT_FAILURE);
                return -1;
        }

	jdh = xmalloc(sizeof(jabber_handler_data_t));
	jdh->session = s;
/*	jdh->roster_retrieved = 0; */
	watch_add(&jabber_plugin, fd, WATCH_READ, jabber_handle_stream, jdh);
	j->using_compress = JABBER_COMPRESSION_NONE;

#ifdef JABBER_HAVE_SSL
	j->send_watch = watch_add_line(&jabber_plugin, fd, WATCH_WRITE_LINE, j->using_ssl ? jabber_handle_write : NULL, j);
#else
	j->send_watch = watch_add_line(&jabber_plugin, fd, WATCH_WRITE_LINE, NULL, NULL);
#endif
	if (!(j->istlen)) {
		watch_write(j->send_watch, 
			"<?xml version=\"1.0\" encoding=\"utf-8\"?><stream:stream to=\"%s\" xmlns=\"jabber:client\" xmlns:stream=\"http://etherx.jabber.org/streams\"%s>", 
			j->server, (session_int_get(s, "use_sasl") == 1) ? " version=\"1.0\"" : "");
	} else {
		watch_write(j->send_watch, "<s v=\'2\'>");
	}

        j->id = 1;
	j->parser = jabber_parser_recreate(NULL, jdh);

	if (j->istlen || (session_int_get(s, "ping-server") != 0)) {
		tname = saprintf("ping-%s", s->uid+4);
		timer_add(&jabber_plugin, tname, j->istlen ? 60 : 180, 1, jabber_ping_timer_handler, xstrdup(s->uid));
		/* w/g dokumentacji do libtlen powinnismy wysylac pinga co 60 sekund */
		xfree(tname);
	}

	return -1;
}

WATCHER(jabber_handle_resolver) /* tymczasowy watcher */
{
	session_t *s = (session_t *) data;
	jabber_private_t *j = jabber_private(s);
	struct in_addr a;
	int one = 1, res;
	struct sockaddr_in sin;
	const int port = session_int_get(s, "port");
#ifdef JABBER_HAVE_SSL
#ifdef JABBER_HAVE_GNUTLS
	/* Allow connections to servers that have OpenPGP keys as well. */
	const int cert_type_priority[3] = {GNUTLS_CRT_X509, GNUTLS_CRT_OPENPGP, 0};
	const int comp_type_priority[3] = {GNUTLS_COMP_ZLIB, GNUTLS_COMP_NULL, 0};
#endif
	int ssl_port = session_int_get(s, "ssl_port");
	int use_ssl = session_int_get(s, "use_ssl");
#endif

	int tlenishub = !session_get(s, "server") && j->istlen;
        if (type) {
                return 0;
	}

        debug_function("[jabber] jabber_handle_resolver()\n", type);
#ifdef NO_POSIX_SYSTEM
	int ret = ReadFile(fd, &a, sizeof(a), &res, NULL);
#else
	res = read(fd, &a, sizeof(a));
#endif
	if ((res != sizeof(a)) || (res && a.s_addr == INADDR_NONE /* INADDR_NONE kiedy NXDOMAIN */)) {
                if (res == -1)
                        debug_error("[jabber] unable to read data from resolver: %s\n", strerror(errno));
                else
                        debug_error("[jabber] read %d bytes from resolver. not good\n", res);
                close(fd);
                print("conn_failed", format_find("conn_failed_resolving"), session_name(s));
                /* no point in reconnecting by jabber_handle_disconnect() */
                j->connecting = 0;
                return -1;
        }

        debug_function("[jabber] resolved to %s\n", inet_ntoa(a));
#ifdef NO_POSIX_SYSTEM
	CloseHandle((HANDLE) fd);
#else
        close(fd);
#endif

        if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
                debug_error("[jabber] socket() failed: %s\n", strerror(errno));
                jabber_handle_disconnect(s, strerror(errno), EKG_DISCONNECT_FAILURE);
                return -1;
        }

        debug_function("[jabber] socket() = %d\n", fd);

        j->fd = fd;

        if (ioctl(fd, FIONBIO, &one) == -1) {
                debug_error("[jabber] ioctl() failed: %s\n", strerror(errno));
                jabber_handle_disconnect(s, strerror(errno), EKG_DISCONNECT_FAILURE);
                return -1;
        }

        /* failure here isn't fatal, don't bother with checking return code */
        setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));

        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = a.s_addr;
#ifdef JABBER_HAVE_SSL
	j->using_ssl = 0;
        if (use_ssl)
                j->port = ssl_port < 1 ? 5223 : ssl_port;
        else
#endif
		j->port = port < 1 ? 5222 : port;

	if (tlenishub) j->port = 80; 

	sin.sin_port = htons(j->port);

        debug_function("[jabber] connecting to %s:%d\n", inet_ntoa(sin.sin_addr), j->port);

        res = connect(fd, (struct sockaddr*) &sin, sizeof(sin));

        if (res == -1 &&
#ifdef NO_POSIX_SYSTEM
		(WSAGetLastError() != WSAEWOULDBLOCK)
#else
		errno != EINPROGRESS
#endif
		) {
                debug_error("[jabber] connect() failed: %s (errno=%d)\n", strerror(errno), errno);
                jabber_handle_disconnect(s, strerror(errno), EKG_DISCONNECT_FAILURE);
                return -1;
        }

#ifdef JABBER_HAVE_SSL
        if (use_ssl) {
		int ret = 0;
#ifdef JABBER_HAVE_OPENSSL
		if (!(j->ssl_session = SSL_new(jabberSslCtx))) {
			print("conn_failed_tls");
			jabber_handle_disconnect(s, SSL_ERROR(ret), EKG_DISCONNECT_FAILURE);
			return -1;
		}
		if (SSL_set_fd(j->ssl_session, fd) == 0) {
			print("conn_failed_tls");
			SSL_free(j->ssl_session);
			j->ssl_session = NULL;
			jabber_handle_disconnect(s, SSL_ERROR(ret), EKG_DISCONNECT_FAILURE);
			return -1;
		}
#endif

#ifdef JABBER_HAVE_GNUTLS
                gnutls_certificate_allocate_credentials(&(j->xcred));
                /* XXX - ~/.ekg/certs/server.pem */
                gnutls_certificate_set_x509_trust_file(j->xcred, "brak", GNUTLS_X509_FMT_PEM);

		if ((ret = SSL_INIT(j->ssl_session))) {
			print("conn_failed_tls");
			jabber_handle_disconnect(s, SSL_ERROR(ret), EKG_DISCONNECT_FAILURE);
			return -1;
		}

		gnutls_set_default_priority(j->ssl_session);
                gnutls_certificate_type_set_priority(j->ssl_session, cert_type_priority);
                gnutls_credentials_set(j->ssl_session, GNUTLS_CRD_CERTIFICATE, j->xcred);
                gnutls_compression_set_priority(j->ssl_session, comp_type_priority);

                /* we use read/write instead of recv/send */
                gnutls_transport_set_pull_function(j->ssl_session, (gnutls_pull_func)read);
                gnutls_transport_set_push_function(j->ssl_session, (gnutls_push_func)write);
		SSL_SET_FD(j->ssl_session, j->fd);
#endif
		watch_add(&jabber_plugin, fd, WATCH_WRITE, jabber_handle_connect_ssl, s);
		return -1;
        } // use_ssl
#endif
	if (j->istlen && tlenishub)	watch_add(&jabber_plugin, fd, WATCH_WRITE, jabber_handle_connect_tlen_hub, s);
	else				watch_add(&jabber_plugin, fd, WATCH_WRITE, jabber_handle_connect, s);
	return -1;
}

#ifdef JABBER_HAVE_SSL
static WATCHER(jabber_handle_connect_ssl) /* tymczasowy */
{
        session_t *s = (session_t *) data;
        jabber_private_t *j = session_private_get(s);
	int ret;

	if (type)
		return 0;

	ret = SSL_HELLO(j->ssl_session);
#ifdef JABBER_HAVE_OPENSSL
	if (ret == -1) {
		ret = SSL_get_error(j->ssl_session, ret);
#else
	{
#endif
		if (SSL_E_AGAIN(ret)) {
			int newfd, direc;
#ifdef JABBER_HAVE_OPENSSL
			direc = (ret != SSL_ERROR_WANT_READ) ? WATCH_WRITE : WATCH_READ;
			newfd = fd;
#else
			direc = gnutls_record_get_direction(j->ssl_session) ? WATCH_WRITE : WATCH_READ;
			newfd = (int) gnutls_transport_get_ptr(j->ssl_session);
#endif

			/* don't create && destroy watch if data is the same... */
			if (newfd == fd && direc == watch) {
				ekg_yield_cpu();
				return 0;
			}

			watch_add(&jabber_plugin, fd, direc, jabber_handle_connect_ssl, s);
			ekg_yield_cpu();
			return -1;
		} else {
#ifdef JABBER_HAVE_GNUTLS
			if (ret >= 0) goto gnutls_ok;	/* gnutls was ok */

			SSL_DEINIT(j->ssl_session);
			gnutls_certificate_free_credentials(j->xcred);
			j->using_ssl = 0;	/* XXX, hack, peres has reported that here j->using_ssl can be 1 (how possible?) hack to avoid double free */
#endif
			jabber_handle_disconnect(s, SSL_ERROR(ret), EKG_DISCONNECT_FAILURE);
			return -1;

		}
	}
gnutls_ok:
	// handshake successful
	j->using_ssl = 1;

	watch_add(&jabber_plugin, fd, WATCH_WRITE, jabber_handle_connect, s);
	return -1;
}
#endif

static QUERY(jabber_protocol_ignore) {
	char *sesion	= *(va_arg(ap, char **));
	char *uid 	= *(va_arg(ap, char **));
/*
	int oldlvl 	= *(va_arg(ap, int *));
	int newlvl 	= *(va_arg(ap, int *));
*/ 
	session_t *s	= session_find(sesion);

	/* check this just to be sure... */
	if (!(session_check(s, 1, "jid"))) return 0;
		/* SPOT rule, first of all here was code to check sesion, valid user, etc... 
		 * 	then send jabber:iq:roster request... with all new & old group...
		 * 	but it was code copied from modify command handler... so here it is.
		 */
	command_exec_format(NULL, s, 0, ("/jid:modify %s -x"), uid);
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
		format_string(format_find("show_status_notavail"));

	print("show_status_status_simple", tmp);
	xfree(tmp);

        // serwer
#ifdef JABBER_HAVE_SSL
	print(j->using_ssl ? "show_status_server_tls" : "show_status_server", j->server, itoa(j->port));
#else
	print("show_status_server", j->server, itoa(j->port));
#endif

	if (session_int_get(s, "__gpg_enabled") == 1)
		print("jabber_gpg_sok", session_name(s), session_get(s, "gpg_key"));
			
        if (j->connecting)
                print("show_status_connecting");
	
	{
		// kiedy ostatnie polaczenie/rozlaczenie
        	time_t n = time(NULL);
        	struct tm *t = localtime(&n);
		int now_days = t->tm_yday;
		char buf[100];
		const char *format;

		t = localtime(&s->last_conn);
		format = format_find((t->tm_yday == now_days) ? "show_status_last_conn_event_today" : "show_status_last_conn_event");
		if (!strftime(buf, sizeof(buf), format, t) && xstrlen(format)>0)
			xstrcpy(buf, "TOOLONG");

		print( (s->connected) ? "show_status_connected_since" : "show_status_disconnected_since", buf);
	}
	return 0;
}

static int jabber_theme_init() {
#ifndef NO_DEFAULT_THEME
	format_add("jabber_auth_subscribe", _("%> (%2) %T%1%n asks for authorisation. Use \"/auth -a %1\" to accept, \"/auth -d %1\" to refuse.%n\n"), 1);
	format_add("jabber_auth_unsubscribe", _("%> (%2) %T%1%n asks for removal. Use \"/auth -d %1\" to delete.%n\n"), 1);
	format_add("jabber_xmlerror", _("%! (%1) Error parsing XML%n\n"), 1);
	format_add("jabber_auth_request", _("%> (%2) Sent authorisation request to %T%1%n.\n"), 1);
	format_add("jabber_auth_accept", _("%> (%2) Authorised %T%1%n.\n"), 1);
	format_add("jabber_auth_unsubscribed", _("%> (%2) Asked %T%1%n to remove authorisation.\n"), 1);
	format_add("jabber_auth_cancel", _("%> (%2) Authorisation for %T%1%n revoked.\n"), 1);
	format_add("jabber_auth_denied", _("%> (%2) Authorisation for %T%1%n denied.\n"), 1);
	format_add("jabber_auth_probe", _("%> (%2) Sent presence probe to %T%1%n.\n"), 1);

	format_add("jabber_msg_failed", _("%! Message to %T%1%n can't be delivered: %R(%2) %r%3%n\n"),1);
	format_add("jabber_msg_failed_long", _("%! Message to %T%1%n %y(%n%K%4(...)%y)%n can't be delivered: %R(%2) %r%3%n\n"),1);
	format_add("jabber_version_response", _("%> Jabber ID: %T%1%n\n%> Client name: %T%2%n\n%> Client version: %T%3%n\n%> Operating system: %T%4%n\n"), 1);
	format_add("jabber_userinfo_response", _("%> Jabber ID: %T%1%n\n%> Full Name: %T%2%n\n%> Nickname: %T%3%n\n%> Birthday: %T%4%n\n%> City: %T%5%n\n%> Desc: %T%6%n\n"), 1);
	format_add("jabber_lastseen_response",	_("%> Jabber ID:  %T%1%n\n%> Logged out: %T%2 ago%n\n"), 1);
	format_add("jabber_lastseen_uptime",	_("%> Jabber ID: %T%1%n\n%> Server up: %T%2 ago%n\n"), 1);
	format_add("jabber_lastseen_idle",      _("%> Jabber ID: %T%1%n\n%> Idle for:  %T%2%n\n"), 1);
	format_add("jabber_unknown_resource", _("%! (%1) User's resource unknown%n\n\n"), 1);
	format_add("jabber_status_notavail", _("%! (%1) Unable to check version, because %2 is unavailable%n\n"), 1);
	format_add("jabber_charset_init_error", _("%! Error initialising charset conversion (%1->%2): %3"), 1);
	format_add("register_change_passwd", _("%> Your password for acount %T%1 is '%T%2%n' change it as fast as you can using command /jid:passwd <newpassword>"), 1);

	/* %1 - session_name, %2 - server/ uid */
	format_add("jabber_privacy_list_begin",   _("%g,+=%G----- Privacy list on %T%2%n"), 1);
	format_add("jabber_privacy_list_item",	  _("%g|| %n %3 - %W%4%n"), 1);					/* %3 - lp %4 - itemname */
	format_add("jabber_privacy_list_item_def",_("%g|| %g Default:%n %W%4%n"), 1);
	format_add("jabber_privacy_list_item_act",_("%g|| %r  Active:%n %W%4%n"), 1); 
	format_add("jabber_privacy_list_end",	  _("%g`+=%G----- End of the privacy list%n"), 1);
	format_add("jabber_privacy_list_noitem",  _("%! No privacy list in %T%2%n"), 1);

	format_add("jabber_privacy_item_header", _("%g,+=%G----- Details for: %T%3%n\n%g||%n JID\t\t\t\t\t  MSG  PIN POUT IQ%n"), 1);
	format_add("jabber_privacy_item",	   "%g||%n %[-44]4 \t%K|%n %[2]5 %K|%n %[2]6 %K|%n %[2]7 %K|%n %[2]8\n", 1);
	format_add("jabber_privacy_item_footer", _("%g`+=%G----- Legend: %n[%3] [%4]%n"), 1);

	/* %1 - item [group, jid, subscri*] */
	format_add("jabber_privacy_item_allow",  "%G%1%n", 1);
	format_add("jabber_privacy_item_deny",   "%R%1%n", 1);

	/* %1 - session_name %2 - list_name %3 xmlns */
	format_add("jabber_private_list_header",  _("%g,+=%G----- Private list: %T%2/%3%n"), 1);

	/* BOOKMARKS */
	format_add("jabber_bookmark_url",	_("%g|| %n URL: %W%3%n (%2)"), 1);		/* %1 - session_name, bookmark  url item: %2 - name %3 - url */
	format_add("jabber_bookmark_conf",	_("%g|| %n MUC: %W%3%n (%2)"), 1);	/* %1 - session_name, bookmark conf item: %2 - name %3 - jid %4 - autojoin %5 - nick %6 - password */

	/* XXX not private_list but CONFIG ? */
	format_add("jabber_private_list_item",	    "%g|| %n %4: %W%5%n",  1);			/* %4 - item %5 - value */
	format_add("jabber_private_list_session",   "%g|| + %n Session: %W%4%n",  1);		/* %4 - uid */
	format_add("jabber_private_list_plugin",    "%g|| + %n Plugin: %W%4 (%5)%n",  1);	/* %4 - name %5 - prio*/
	format_add("jabber_private_list_subitem",   "%g||  - %n %4: %W%5%n",  1);               /* %4 - item %5 - value */

	format_add("jabber_private_list_footer",  _("%g`+=%G----- End of the private list%n"), 1);
	format_add("jabber_private_list_empty",	  _("%! No list: %T%2/%3%n"), 1);

	/* %1 - session_name, %2 - uid (*_item: %3 - agent uid %4 - description %5 - seq id) */
	format_add("jabber_transport_list_begin", _("%g,+=%G----- Avalible agents on: %T%2%n"), 1);
	format_add("jabber_transport_list_item",  _("%g|| %n %6 - %W%3%n (%5)"), 1);
	format_add("jabber_transport_list_item_node",("%g|| %n %6 - %W%3%n node: %g%4%n (%5)"), 1);
	format_add("jabber_transport_list_end",   _("%g`+=%G----- End of the agents list%n\n"), 1);
	format_add("jabber_transport_list_nolist", _("%! No agents @ %T%2%n"), 1);

	format_add("jabber_remotecontrols_list_begin", _("%g,+=%G----- Avalible remote controls on: %T%2%n"), 1);
	format_add("jabber_remotecontrols_list_item",  _("%g|| %n %6 - %W%4%n (%5)"), 1);		/* %3 - jid %4 - node %5 - descr %6 - seqid */
	format_add("jabber_remotecontrols_list_end",   _("%g`+=%G----- End of the remote controls list%n\n"), 1);
	format_add("jabber_remotecontrols_list_nolist", _("%! No remote controls @ %T%2%n"), 1);
	format_add("jabber_remotecontrols_executing",	_("%> (%1) Executing command: %W%3%n @ %W%2%n (%4)"), 1);
	format_add("jabber_remotecontrols_completed",	_("%> (%1) Command: %W%3%n @ %W%2 %gcompleted"), 1);

	format_add("jabber_remotecontrols_preparing",	_("%> (%1) Remote client: %W%2%n is preparing to execute command @node: %W%3"), 1);	/* %2 - uid %3 - node */
	format_add("jabber_remotecontrols_commited",	_("%> (%1) Remote client: %W%2%n executed command @node: %W%3"), 1);			/* %2 - uid %3 - node */
	format_add("jabber_remotecontrols_commited_status", _("%> (%1) RC %W%2%n: requested changing status to: %3 %4 with priority: %5"), 1);	/* %3 - status %4 - descr %5 - prio */
		/* %3 - command+params %4 - sessionname %5 - target %6 - quiet */
	format_add("jabber_remotecontrols_commited_command",_("%> (%1) RC %W%2%n: requested command: %W%3%n @ session: %4 window: %5 quiet: %6"), 1);	

	format_add("jabber_transinfo_begin",	_("%g,+=%G----- Information about: %T%2%n"), 1);
	format_add("jabber_transinfo_begin_node",_("%g,+=%G----- Information about: %T%2%n (%3)"), 1);
	format_add("jabber_transinfo_identify",	_("%g|| %G --== %g%3 %G==--%n"), 1);
		/* %4 - real fjuczer name  %3 - translated fjuczer name. */
	format_add("jabber_transinfo_feature",	_("%g|| %n %W%2%n feature: %n%3"), 1);
	format_add("jabber_transinfo_comm_ser",	_("%g|| %n %W%2%n can: %n%3 %2 (%4)"), 1);
	format_add("jabber_transinfo_comm_use",	_("%g|| %n %W%2%n can: %n%3 $uid (%4)"), 1);
	format_add("jabber_transinfo_comm_not",	_("%g|| %n %W%2%n can: %n%3 (%4)"), 1);
	format_add("jabber_transinfo_end",	_("%g`+=%G----- End of the infomations%n\n"), 1);

	format_add("jabber_search_item",	_("%) JID: %T%3%n\n%) Nickname:  %T%4%n\n%) Name: %T%5 %6%n\n%) Email: %T%7%n\n"), 1);	/* like gg-search_results_single */
		/* %3 - jid %4 - nickname %5 - firstname %6 - surname %7 - email */
	format_add("jabber_search_begin",	_("%g,+=%G----- Search on %T%2%n"), 1);
//	format_add("jabber_search_items", 	  "%g||%n %[-24]3 %K|%n %[10]5 %K|%n %[10]6 %K|%n %[12]4 %K|%n %[16]7\n", 1);		/* like gg-search_results_multi. TODO */
	format_add("jabber_search_items",	  "%g||%n %3 - %5 '%4' %6 <%7>", 1);
	format_add("jabber_search_end",		_("%g`+=%G-----"), 1);
	format_add("jabber_search_error",	_("%! Error while searching: %3\n"), 1);

	format_add("jabber_form_title",		  "%g,+=%G----- %3 %n(%T%2%n)", 1);
	format_add("jabber_form_item",		  "%g|| %n%(21)3 (%6) %K|%n --%4 %(20)5", 1); 	/* %3 - label %4 - keyname %5 - value %6 - req; optional */

	format_add("jabber_form_item_beg",	  "%g|| ,+=%G-----%n", 1);
	format_add("jabber_form_item_plain",	  "%g|| | %n %3: %5", 1);			/* %3 - label %4 - keyname %5 - value */
	format_add("jabber_form_item_end",	  "%g|| `+=%G-----%n", 1);

	format_add("jabber_form_item_val",	  "%K[%b%3%n %g%4%K]%n", 1);			/* %3 - value %4 - label */
	format_add("jabber_form_item_sub",        "%g|| %|%n\t%3", 1);			/* %3 formated jabber_form_item_val */

	format_add("jabber_form_command",	_("%g|| %nType %W/%3 %g%2 %W%4%n"), 1); 
	format_add("jabber_form_instructions", 	  "%g|| %n%|%3", 1);
	format_add("jabber_form_end",		_("%g`+=%G----- End of this %3 form ;)%n"), 1);

	format_add("jabber_registration_item", 	  "%g|| %n            --%3 %4%n", 1); /* %3 - keyname %4 - value */ /* XXX, merge */
	
	/* %1 - session %2 - message %3 - start %4 - end */
	format_add("jabber_vacation", _("%> You'd set up your vacation status: %g%2%n (since: %3 expires@%4)"), 1);

	/* %1 - sessionname %2 - mucjid %3 - nickname %4 - text %5 - atr */
	format_add("jabber_muc_recv", 	"%B<%w%X%5%3%B>%n %4", 1);
	format_add("jabber_muc_send",	"%B<%n%X%5%W%3%B>%n %4", 1);

	format_add("jabber_muc_room_created", 
		_("%> Room %W%2%n created, now to configure it: type %W/admin %g%2%n to get configuration form, or type %W/admin %g%2%n --instant to create instant one"), 1);
	format_add("jabber_muc_banlist", _("%g|| %n %5 - %W%2%n: ban %c%3%n [%4]"), 1);	/* %1 sesja %2 kanal %3 kto %4 reason %5 numerek */
#if 0
	format_add("jabber_send_chan", _("%B<%W%2%B>%n %5"), 1);
	format_add("jabber_send_chan_n", _("%B<%W%2%B>%n %5"), 1);

	format_add("jabber_recv_chan", _("%b<%w%2%b>%n %5"), 1);
	format_add("jabber_recv_chan_n", _("%b<%w%2%b>%n %5"), 1);
#endif
		/* %1 sesja %2 nick %3 - jid %4 - kanal %6 - role %7 affiliation*/
	format_add("muc_joined", 	_("%> %C%2%n %B[%c%3%B]%n has joined %W%4%n as a %g%6%n and a %g%7%n"), 1);
		/* %1 sesja %2 nick %3 - jid %4 - kanal %5 - reason */
	format_add("muc_left",		_("%> %c%2%n [%c%3%n] has left %W%4 %n[%5]\n"), 1);

			/* %1 - sesja, %2 - serwer, %3 - nazwa, %4 - XMLNS, %5 - z czym sie je */
	format_add("xmpp_feature_header", _("%g,+=%G----- XMPP features %n(%T%2%n%3%n)"), 1);	/* %3 - todo */
	format_add("xmpp_feature",	  _("%g|| %n %W%2%n can: %5 [%G%3%g,%4%n]"), 1);
	format_add("xmpp_feature_sub",	  _("%g|| %n     %W%3%n: %5 [%G%4%n]"), 1);
	format_add("xmpp_feature_unknown",_("%g|| %n %W%2%n feature: %r%3 %n[%G%3%g,%4%n]"), 1);
	format_add("xmpp_feature_footer", _("%g`+=%G----- %n Turn it off using: /session display_server_features 0\n"), 1);

	format_add("gmail_new_mail", 	  _("%> (%1) Content of your mailbox have changed or new mail arrived."), 1);	/* sesja */
	format_add("gmail_count", 	  _("%> (%1) You have %T%2%n new thread(s) on your gmail account."), 1);	/* sesja, mail count */
	format_add("gmail_mail", 	  "%>    %|%T%2%n - %g%3%n\n", 1);						/* sesja, from, topic, [UNUSED messages count in thread (?1)] */
	format_add("gmail_thread",	  "%>    %|%T%2 [%4]%n - %g%3%n\n", 1);						/* sesja, from, topic, messages count in thread */
	format_add("tlen_mail",		_("%> (%1) New mail from %T%2%n, with subject: %G%3%n"), 1); 			/* sesja, from, topic */
	format_add("tlen_alert", 	_("%> (%1) %T%2%n sent us an alert ...%n"), 1); 				/* sesja, from */

	format_add("jabber_gpg_plugin",	_("%> (%1) To use OpenGPG support in jabber, first load gpg plugin!"), 1);	/* sesja */
	format_add("jabber_gpg_config",	_("%> (%1) First set gpg_key and gpg_password before turning on gpg_active!"), 1); /* sesja */
	format_add("jabber_gpg_ok",	_("%) (%1) GPG support: %gENABLED%n using key: %W%2%n"), 1);			/* sesja, klucz */
	format_add("jabber_gpg_sok",	_("%) GPG key: %W%2%n"), 1);							/* sesja, klucz for /status */
	format_add("jabber_gpg_fail", 	_("%> (%1) We didn't manage to sign testdata using key: %W%2%n (%R%3%n)\n"	/* sesja, klucz, error */
					"OpenGPG support for this session disabled."), 1);
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

static QUERY(jabber_pgp_postinit) {
	list_t l;

	session_postinit = 1;

	for (l = sessions; l; l = l->next) {
		session_t *s = l->data;

		if (!xstrncmp(s->uid, "jid:", 4)) 
			jabber_gpg_changed(s, NULL);
	}
	return 0;
}

static plugins_params_t jabber_plugin_vars[] = {
	PLUGIN_VAR_ADD("alias", 		SESSION_VAR_ALIAS, VAR_STR, 0, 0, NULL),
	/* '666' enabled for everyone (DON'T TRY IT!); '0' - disabled; '1' - enabled for the same id (allow from diffrent resources); '2' - enabled for allow_remote_control_jids (XXX) */
	PLUGIN_VAR_ADD("allow_remote_control",	0, VAR_INT, "0", 0, NULL),
	PLUGIN_VAR_ADD("allow_autoresponder",	SESSION_VAR_ALLOW_AUTORESPONDER, VAR_BOOL, "0", 0, NULL),
	PLUGIN_VAR_ADD("auto_auth",		0, VAR_INT, "0", 0, NULL),
	PLUGIN_VAR_ADD("auto_away", 		SESSION_VAR_AUTO_AWAY, VAR_INT, "0", 0, NULL),
	PLUGIN_VAR_ADD("auto_away_descr",	SESSION_VAR_AUTO_AWAY_DESCR, VAR_STR, 0, 0, NULL),
	PLUGIN_VAR_ADD("auto_back", 		SESSION_VAR_AUTO_BACK, VAR_INT, "0", 0, NULL),
	PLUGIN_VAR_ADD("auto_bookmark_sync", 	0, VAR_BOOL, "0", 0, NULL),
	PLUGIN_VAR_ADD("auto_privacylist_sync", 0, VAR_BOOL, "0", 0, NULL),
	PLUGIN_VAR_ADD("auto_connect", 		SESSION_VAR_AUTO_CONNECT, VAR_INT, "0", 0, NULL),
	PLUGIN_VAR_ADD("auto_find", 		SESSION_VAR_AUTO_FIND, VAR_INT, "0", 0, NULL),
	PLUGIN_VAR_ADD("auto_reconnect", 	SESSION_VAR_AUTO_RECONNECT, VAR_INT, "0", 0, NULL),
	PLUGIN_VAR_ADD("auto_xa", 		SESSION_VAR_AUTO_XA, VAR_INT, "0", 0, NULL),
	PLUGIN_VAR_ADD("auto_xa_descr", 	SESSION_VAR_AUTO_XA_DESCR, VAR_STR, 0, 0, NULL),
	PLUGIN_VAR_ADD("display_notify", 	SESSION_VAR_DISPLAY_NOTIFY, VAR_INT, "0", 0, NULL),
	PLUGIN_VAR_ADD("display_server_features", 0, VAR_INT, "1", 0, NULL),
	PLUGIN_VAR_ADD("gpg_active", 		0, VAR_BOOL, "0", 0, jabber_gpg_changed),
	PLUGIN_VAR_ADD("gpg_key", 		0, VAR_STR, NULL, 0, jabber_gpg_changed),
	PLUGIN_VAR_ADD("gpg_password", 		0, VAR_STR, NULL, 1, jabber_gpg_changed),
	PLUGIN_VAR_ADD("log_formats", 		SESSION_VAR_LOG_FORMATS, VAR_STR, "xml,simple", 0, NULL),
	PLUGIN_VAR_ADD("password", 		SESSION_VAR_PASSWORD, VAR_STR, "foo", 1, NULL),
	PLUGIN_VAR_ADD("plaintext_passwd", 	0, VAR_INT, "0", 0, NULL),
	PLUGIN_VAR_ADD("ping-server", 		0, VAR_BOOL, "0", 0, NULL),
	PLUGIN_VAR_ADD("port", 			SESSION_VAR_PORT, VAR_INT, "5222", 0, NULL),
	PLUGIN_VAR_ADD("priority", 		0, VAR_INT, "5", 0, NULL),
	PLUGIN_VAR_ADD("privacy_list", 		0, VAR_STR, 0, 0, NULL),
	PLUGIN_VAR_ADD("resource", 		0, VAR_STR, 0, 0, NULL),
	PLUGIN_VAR_ADD("server", 		SESSION_VAR_SERVER, VAR_STR, 0, 0, NULL),
	PLUGIN_VAR_ADD("ssl_port", 		0, VAR_INT, "5223", 0, NULL),
	PLUGIN_VAR_ADD("use_compression", 	0, VAR_STR, 0, 0, NULL),		/* for instance: zlib,lzw */
	PLUGIN_VAR_ADD("use_sasl", 		0, VAR_BOOL, "0", 0, NULL),
	PLUGIN_VAR_ADD("use_ssl", 		0, VAR_BOOL, "0", 0, NULL),
	PLUGIN_VAR_ADD("use_tls", 		0, VAR_BOOL, "0", 0, NULL),
	PLUGIN_VAR_ADD("ver_client_name", 	0, VAR_STR, 0, 0, NULL),
	PLUGIN_VAR_ADD("ver_client_version", 	0, VAR_STR, 0, 0, NULL),
	PLUGIN_VAR_ADD("ver_os", 		0, VAR_STR, 0, 0, NULL),

	PLUGIN_VAR_END()
};

int jabber_plugin_init(int prio) {
	jabber_plugin.params = jabber_plugin_vars;

        plugin_register(&jabber_plugin, prio);

	session_postinit = 0;

	query_connect_id(&jabber_plugin, PROTOCOL_VALIDATE_UID,	jabber_validate_uid, NULL);
	query_connect_id(&jabber_plugin, PLUGIN_PRINT_VERSION,	jabber_print_version, NULL);
	query_connect_id(&jabber_plugin, GET_PLUGIN_PROTOCOLS,	jabber_protocols, NULL);
	query_connect_id(&jabber_plugin, SESSION_ADDED,		jabber_session, (void*) 1);
	query_connect_id(&jabber_plugin, SESSION_REMOVED,	jabber_session, (void*) 0);
	query_connect_id(&jabber_plugin, STATUS_SHOW,		jabber_status_show_handle, NULL);
	query_connect_id(&jabber_plugin, UI_WINDOW_KILL,	jabber_window_kill, NULL);
	query_connect_id(&jabber_plugin, PROTOCOL_IGNORE,	jabber_protocol_ignore, NULL);
	query_connect_id(&jabber_plugin, CONFIG_POSTINIT,	jabber_dcc_postinit, NULL);
	query_connect_id(&jabber_plugin, CONFIG_POSTINIT,	jabber_pgp_postinit, NULL);

/* XXX, set-vars-default */
	variable_add(&jabber_plugin, ("beep_mail"), VAR_BOOL, 1, &config_jabber_beep_mail, NULL, NULL, NULL);
	variable_add(&jabber_plugin, ("dcc"), VAR_BOOL, 1, &jabber_dcc, (void*) jabber_dcc_postinit, NULL, NULL);
	variable_add(&jabber_plugin, ("dcc_ip"), VAR_STR, 1, &jabber_dcc_ip, NULL, NULL, NULL);
	variable_add(&jabber_plugin, ("default_pubsub_server"), VAR_STR, 1, &jabber_default_pubsub_server, NULL, NULL, NULL);
	variable_add(&jabber_plugin, ("default_search_server"), VAR_STR, 1, &jabber_default_search_server, NULL, NULL, NULL);

        jabber_register_commands();
#ifdef JABBER_HAVE_SSL
	SSL_GLOBAL_INIT();
#endif
        return 0;
}

static int jabber_plugin_destroy() {
#ifdef JABBER_HAVE_SSL
	SSL_GLOBAL_DEINIT();
#endif
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
 * vim: sts=8 sw=8
 */
