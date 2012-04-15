/*
 *  (C) Copyright 2006 Jakub Zawadzki <darkjames@darkjames.ath.cx>
 *		  2012 Wiesław Ochmiński <wiechu at wiechu dot com>
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

#include <string.h>

#define NNTP_ONLY         SESSION_MUSTBELONG | SESSION_MUSTHASPRIVATE
#define NNTP_FLAGS        NNTP_ONLY  | SESSION_MUSTBECONNECTED
#define NNTP_FLAGS_TARGET NNTP_FLAGS | COMMAND_ENABLEREQPARAMS | COMMAND_PARAMASTARGET

#define nntp_private(s) ((s && s->priv) ? ((feed_private_t *) s->priv)->priv_data : NULL)

extern plugin_t nntp_plugin;

typedef struct {
	void *priv_data;
} feed_private_t;

static int nntp_theme_init();
PLUGIN_DEFINE(nntp, PLUGIN_PROTOCOL, nntp_theme_init);

void *nntp_protocol_init();
void nntp_protocol_deinit(void *priv);
void nntp_init();

static QUERY(nntp_validate_uid)
{
	char *uid = *(va_arg(ap, char **));
	int *valid = va_arg(ap, int *);

	if (!uid)
		return 0;
	if (!xstrncasecmp(uid, "nntp:", 5)) {
		(*valid)++;
		return -1;
	}

	return 0;
}

static QUERY(nntp_session_init) {
	char *session = *(va_arg(ap, char**));
	session_t *s = session_find(session);

	feed_private_t *j;

	if (!s || s->priv || s->plugin != &nntp_plugin)
		return 1;

	j = xmalloc(sizeof(feed_private_t));
	j->priv_data = nntp_protocol_init();

	s->priv = j;
	userlist_read(s);
	return 0;
}

static QUERY(nntp_session_deinit) {
	char *session = *(va_arg(ap, char**));
	session_t *s = session_find(session);

	feed_private_t *j;

	if (!s || !(j = s->priv) || s->plugin != &nntp_plugin)
		return 1;

	userlist_write(s);
	config_commit();
	s->priv			= NULL;
	nntp_protocol_deinit(j->priv_data);

	xfree(j);

	return 0;
}

// #define EKG_WINACT_RSS EKG_WINACT_MSG // till 4616
#define EKG_WINACT_RSS EKG_WINACT_IMPORTANT

	/* new:
	 *	0x0 - old
	 *	0x1 - new
	 *	0x2 - modified
	 */

	/* mtags: (by default nntp_message() won't display any messages if new == 0, but if user want to display again (?) news, we must allow him)
	 *	0x0 - none
	 *	0x8 - display all headers / sheaders
	 */

static QUERY(nntp_message) {
	char *session	= *(va_arg(ap, char **));
	char *uid	= *(va_arg(ap, char **));
	char *sheaders	= *(va_arg(ap, char **));
	char *headers	= *(va_arg(ap, char **));
	char *title	= *(va_arg(ap, char **));
	char *url	= *(va_arg(ap, char **));
	char *body	= *(va_arg(ap, char **));

	int *new	= va_arg(ap, int *);		/* 0 - old; 1 - new; 2 - modified */
	int mtags	= *(va_arg(ap, int *));

	session_t *s	= session_find(session);
	char *tmp;

	const char *dheaders	= session_get(s, "display_headers");
	const char *dsheaders	= session_get(s, "display_server_headers");
	int dmode		= session_int_get(s, "display_mode");
	int mw			= session_int_get(s, "make_window");

	const char *target	= NULL;
	window_t *targetwnd	= NULL;

	if (*new == 0 && !mtags) return 0;

	if (mtags)	/* XXX */
		dmode = mtags;

	switch (mw) {			/* XXX, __current ? */
		case 0:
			target = "__status";
			targetwnd = window_status;
			break;
		case 1:
			target = session;
			break;
		case 2:
		default:
			if (!(target = get_nickname(s, uid)))
				target = uid;
			break;
	}

	if (mw)
		targetwnd = window_new(target, s, 0);

	switch (dmode) {
		case 0:	 print_window_w(targetwnd, EKG_WINACT_RSS, "nntp_message_new", title, url);	/* only notify */
		case -1: return 0;							/* do nothing */

		case 2:	body		= NULL;					/* only headers */
		case 1:	if (dmode == 1) headers = NULL;				/* only body */
		default:							/* default: 3 (body+headers) */
		case 3:	sheaders = NULL;					/* headers+body */
		case 4:	break;							/* shreaders+headers+body */
	}

	print_window_w(targetwnd, EKG_WINACT_RSS, "nntp_message_header", title, url);

	if (sheaders) {
		char *str = xstrdup(sheaders);
		char *formated = NULL;
		while ((tmp = split_line(&str))) {
			char *value = NULL;
			char *formatka;

			if ((value = xstrchr(tmp, ' '))) *value = 0;
			if (dsheaders && !xstrstr(dsheaders, tmp)) {
/*				debug("DSHEADER: %s=%s skipping..\n", tmp, value+1); */
				continue;	/* jesli mamy display_server_headers a tego nie mamy na liscie to pomijamy */
			}

			formatka = saprintf("nntp_server_header_%s", tmp);
			formatka[xstrlen(formatka)-1] = '\0';
			if (!format_exists(formatka)) {
				g_free(formatka);
				formatka = g_strdup("nntp_server_header_generic");
			}

			formated = format_string(format_find(formatka), tmp, value ? value+1 : "");
			print_window_w(targetwnd, EKG_WINACT_RSS, "nntp_message_body", formated ? formated : tmp);

			g_free(formated);
			g_free(formatka);
		}
		if (headers || body) print_window_w(targetwnd, EKG_WINACT_RSS, "nntp_message_body", "");	/* rozdziel */
	}

	if (headers) {
		char *str, *org;
		str = org = xstrdup(headers);
		char *formated = NULL;
		while ((tmp = split_line(&str))) {
			char *value = NULL;
			char *formatka;

			if ((value = xstrchr(tmp, ' '))) *value = 0;
			if (dheaders && !xstrstr(dheaders, tmp)) {
				if (value)
					debug("DHEADER: %s=%s skipping...\n", tmp, value+1);
				else	debug("DHEADER: %s skipping.. (tag without value?)\n", tmp);
				continue;	/* jesli mamy display_headers a tego nie mamy na liscie to pomijamy */
			}

			formatka = saprintf("nntp_message_header_%s", tmp);
			formatka[xstrlen(formatka)-1] = '\0';
			if (!format_exists(formatka)) {
				xfree(formatka);
				formatka = g_strdup("nntp_message_header_generic");
			}

			formated = format_string(format_find(formatka), tmp, value ? value+1 : "");
			print_window_w(targetwnd, EKG_WINACT_RSS, "nntp_message_body", formated ? formated : tmp);

			g_free(formated);
			g_free(formatka);
		}
		if (body) print_window_w(targetwnd, EKG_WINACT_RSS, "nntp_message_body", "");	/* rozdziel */
		xfree(org);
	}

	if (body) {
		int article_signature	= 0;
		char *str, *org;
		str = org = xstrdup(body);

		while ((tmp = split_line(&str))) {
			char *formated = NULL;

			if (!xstrcmp(tmp, "-- ")) article_signature = 1;
			if (article_signature) {
				formated = format_string(format_find("nntp_message_signature"), tmp);
			} else {
				int i;
				char *quote_name = NULL;
				const char *f = NULL;
				for (i = 0; i < xstrlen(tmp) && tmp[i] == '>'; i++);

				if (i > 0) {
					quote_name = saprintf("nntp_message_quote_level%d", i);

					f = format_find(quote_name);
					if (!format_ok(f)) {
						debug("[NNTP, QUOTE] format: %s not found, using global one...\n", quote_name);
						f = format_find("nntp_message_quote_level");
					}
					g_free(quote_name);
				}
				if (f && f[0] != '\0')
					formated = format_string(f, tmp);
			}

			print_window_w(targetwnd, EKG_WINACT_RSS, "nntp_message_body", formated ? formated : tmp);
			g_free(formated);
		}
		g_free(org);
	}

	print_window_w(targetwnd, EKG_WINACT_RSS, "nntp_message_footer");

	*new = 0;
	return 0;
}

void nntp_set_status(userlist_t *u, int status) {
	if (!u || !status) return;

/*	if (xstrcmp(u->status, status)) print("nntp_status", u->uid, status, u->descr); */
	u->status	= status;
}

void nntp_set_descr(userlist_t *u, char *descr) {
	char *tmp;
	if (!u || !descr) return;

/*	if (xstrcmp(u->descr, descr)) print("nntp_status", u->uid, u->status, descr); */
	tmp		= u->descr;
	u->descr	= descr;
	xfree(tmp);
}

void nntp_set_statusdescr(userlist_t *u, int status, char *descr) {
	nntp_set_status(u, status);
	nntp_set_descr(u, descr);
}

static plugins_params_t nntp_plugin_vars[] = {
	PLUGIN_VAR_ADD("alias",			VAR_STR, NULL, 0, NULL),
	/* (-1 - nothing; 0 - only notify; 1 - only body; 2 - only headers; 3 - headers+body 4 - sheaders+headers+ body)  default+else: 3 */
	PLUGIN_VAR_ADD("display_mode",		VAR_INT, "3", 0, NULL),

	PLUGIN_VAR_ADD("display_headers",	VAR_STR,
				"From: Date: Newsgroups: Subject: User-Agent: NNTP-Posting-Host:",
			0, NULL),
	/* 0 - status; 1 - all in one window (s->uid) 2 - seperate windows per feed / group. default+else: 2 */
	PLUGIN_VAR_ADD("make_window",		VAR_INT, "2", 0, NULL),
	PLUGIN_VAR_ADD("auto_connect",		VAR_BOOL, "0", 0, NULL),
	PLUGIN_VAR_ADD("username",		VAR_STR, NULL, 0, NULL),
	PLUGIN_VAR_ADD("password",		VAR_STR, NULL, 1, NULL),
	PLUGIN_VAR_ADD("port",			VAR_INT, "119", 0, NULL),
	PLUGIN_VAR_ADD("server",		VAR_STR, NULL, 0, NULL),

	PLUGIN_VAR_END()
};

EXPORT int nntp_plugin_init(int prio) {
	PLUGIN_CHECK_VER("nntp");

	nntp_plugin.params = nntp_plugin_vars;
	plugin_register(&nntp_plugin, prio);
	query_connect(&nntp_plugin, "session-added", nntp_session_init, NULL);
	query_connect(&nntp_plugin, "session-removed", nntp_session_deinit, NULL);
	query_connect(&nntp_plugin, "protocol-validate-uid", nntp_validate_uid, NULL);
	query_connect(&nntp_plugin, "nntp-message", nntp_message, NULL);  // TODO: Rename to nntp-message
	nntp_init();
	return 0;
}

static int nntp_plugin_destroy() {
	plugin_unregister(&nntp_plugin);
	return 0;
}

static int nntp_theme_init() {
#ifndef NO_DEFAULT_THEME
	format_add("nntp_command_help_header",	_("%g,+=%G----- %2 %n(%T%1%n)"), 1);
	format_add("nntp_command_help_item",	_("%g|| %W%1: %n%2"), 1);
	format_add("nntp_command_help_footer",	_("%g`+=%G----- End of 100%n\n"), 1);

	format_add("nntp_message_quote_level1",	"%y%1", 1);
	format_add("nntp_message_quote_level2", "%g%1", 1);
	format_add("nntp_message_quote_level3", "%r%1", 1);
	format_add("nntp_message_quote_level4", "%c%1", 1);
	format_add("nntp_message_quote_level",	"%B%1", 1);	/* upper levels.. */
	format_add("nntp_message_signature",	"%B%1", 1);

	format_add("nntp_message_header",	_("%g,+=%G-----%y  %1 %n(ID: %W%2%n)"), 1);
	format_add("nntp_message_body",		_("%g||%n %|%1"), 1);
	format_add("nntp_message_footer",	_("%g|+=%G----- End of message...%n\n"), 1);

	format_add("nntp_message_header_generic",	_("%r %1 %W%2"), 1);

	format_add("nntp_posting_failed",	_("(%1) Posting to group: %2 failed: %3 (post saved in: %4)"), 1);
	format_add("nntp_posting",		_("(%1) Posting to group: %2 Subject: %3...."), 1);
#endif
	return 0;
}

typedef enum {
	NNTP_IDLE = 0,
	NNTP_CHECKING,
	NNTP_DOWNLOADING,
} nntp_newsgroup_state_t;

typedef struct {
	int artid;
	char *msgid;
	int new;
	string_t header;
	string_t body;
} nntp_article_t;

typedef struct {
	char *uid;
	char *name;
	nntp_newsgroup_state_t state;

	int article;	/* current */

	int fart;	/* first article in the group		*/
	int cart;	/* current artcile (downloading)	*/
	int lart;	/* last article				*/
	list_t articles;/* list of articles, nntp_article_t	*/
} nntp_newsgroup_t;

typedef struct {
	int connecting;
	connection_data_t *connection;

	int lock;
	int authed;

	int last_code;			/* last code */
	nntp_newsgroup_t *newsgroup;	/* current newsgroup */

	string_t buf;
	list_t newsgroups;

} nntp_private_t;

void nntp_write(session_t *session, const gchar *format, ...) {
	nntp_private_t *j = nntp_private(session);
	char *tmp, **lines;
	va_list args;
	int i;

	va_start(args, format);
	tmp = g_strdup_vprintf(format, args);
	lines = g_strsplit(tmp, "\r\n", 0);
	for (i=0; lines[i]; i++)
		if (*lines[i])
			debug_io("nntp_write(0x%x) %s\n", session, lines[i]);
	ekg2_connection_write(j->connection, tmp, xstrlen(tmp));
	g_strfreev(lines);
	xfree(tmp);
	va_end(args);
}

static nntp_article_t *nntp_article_find(nntp_newsgroup_t *group, int articleid, char *msgid) {
	nntp_article_t *article;
	list_t l;

	for (l = group->articles; l; l = l->next) {
		article = l->data;

		if (article->artid == articleid) {
			if (!article->msgid && msgid) article->msgid = xstrdup(msgid);
			return article;
		}
	}
	article		= xmalloc(sizeof(nntp_article_t));
	article->new	= 1;
	article->artid	= articleid;
	article->msgid	= xstrdup(msgid);
	article->header	= string_init(NULL);
	article->body	= string_init(NULL);

	list_add(&group->articles, article);
	return article;
}

static nntp_newsgroup_t *nntp_newsgroup_find(session_t *s, const char *name) {
	nntp_private_t *j = nntp_private(s);
	list_t l;
	nntp_newsgroup_t *newsgroup;

	for (l = j->newsgroups; l; l = l->next) {
		newsgroup = l->data;

		debug("nntp_newsgroup_find() %s %s\n", newsgroup->name, name);
		if (!xstrcmp(newsgroup->name, name))
			return newsgroup;
	}
	debug("nntp_newsgroup_find() 0x%x NEW %s\n", j->newsgroups, name);

	newsgroup	= xmalloc(sizeof(nntp_newsgroup_t));
	newsgroup->uid	= saprintf("nntp:%s", name);
	newsgroup->name = xstrdup(name);

	list_add(&(j->newsgroups), newsgroup);
	return newsgroup;
}

static void nntp_handle_disconnect(session_t *s, const char *reason, int type) {
	nntp_private_t *j = nntp_private(s);

	if (!j)
		return;

	if (j->newsgroup)
		j->newsgroup->state = NNTP_IDLE;
	j->newsgroup = NULL;

	j->last_code	= -1;
	j->authed	= 0;

	j->connecting = 0;

	protocol_disconnected_emit(s, reason, type);

	ekg2_connection_close(&j->connection);
}

typedef struct {
	char *session;
	char *filename;
	char *newsgroup;
	char *subject;

	time_t last_mtime;
} nntp_children_t;

#if 0
static void nntp_children_died(GPid pid, gint status, gpointer data) {
	nntp_children_t *d = data;
	session_t *s = session_find(d->session);
	struct stat st;

	if (!s || !s->priv) {
		print("nntp_posting_failed", session_name(s), d->newsgroup, "session not found", d->filename);
		goto fail;
	}

	if ((stat(d->filename, &st) != 0)) {
		print("nntp_posting_failed", session_name(s), d->newsgroup, "fstat() failed", d->filename);
		goto fail;
	}

	if (st.st_ctime <= d->last_mtime) {
		print("nntp_posting_failed", session_name(s), d->newsgroup, "mtime not changed", d->filename);
		goto fail;
	}

	print("nntp_posting", session_name(s), d->newsgroup, d->subject);

fail:
	xfree(d->session);
	xfree(d->filename);
	xfree(d->newsgroup);
	xfree(d->subject);
	xfree(d);
}
#endif

#define NNTP_HANDLER(x) static int x(session_t *s, int code, char *str, void *data)
typedef int (*nntp_handler) (session_t *, int, char *, void *);


NNTP_HANDLER(nntp_help_process) {			/* 100 */
	debug_function("nntp_help_process() %s\n", str);

//	format_add("nntp_command_help_header",	_("%g,+=%G----- %2 %n(%T%1%n)"), 1);
//	format_add("nntp_command_help_item",	_("%g|| %W%1: %n%2"), 1);
//	format_add("nntp_command_help_footer",	_("%g`+=%G----- End of 100%n\n"), 1);
	return 0;
}

static char hextochar(char t) {
	if (t >= '0' && t <= '9')
		return t - '0';
	else if (t >= 'A' && t <= 'F')
		return 10+(t - 'A');
	else if (t >= 'a' && t <= 'f')
		return 10+(t - 'a');
	debug_error("hextochar() invalid char: %d\n", t);
	return 0;
}

NNTP_HANDLER(nntp_message_process) {			/* 220, 221, 222 */
	nntp_private_t *j	= nntp_private(s);
	int article_headers	= (code == 220 || code == 221);
	int article_body	= (code == 220 || code == 222);
	char *mbody, **tmpbody;
	char *content_charset = NULL;
	enum {
		ENCODING_UNKNOWN = 0,
		ENCODING_BASE64,
		ENCODING_QUOTEDPRINTABLE,
		ENCODING_8BIT,
	} cte = ENCODING_UNKNOWN;	/* Content-Transfer-Encoding: */

	nntp_article_t *art = NULL;

	if (!(mbody = split_line(&str))) return -1;

	tmpbody = array_make(mbody, " ", 3, 1, 0);		/* header [id <message-id> type] */

	if (!tmpbody || !tmpbody[0] || !tmpbody[1] || !tmpbody[2]) {
		debug("nntp_message_process() tmpbody? mbody: %s\n", mbody);
		g_strfreev(tmpbody);
		return -1;
	}

	if (!(art = nntp_article_find(j->newsgroup, atoi(tmpbody[0]), tmpbody[1]))) {
		debug("nntp_message_process nntp_article_find() failed\n");
		g_strfreev(tmpbody);
		return -1;
	}

	if (article_headers)	string_clear(art->header);
	if (article_body)	string_clear(art->body);

	if (article_headers && article_body) {
		char *tmp;
		if ((tmp = xstrstr(str, "\n\n"))) {
			string_append_n(art->header, str, tmp-str-1);
			str = tmp + 2;		/* +\r\n */
		} else {
			debug("ERROR, It's really article_headers with article_body?!\n");
		}
	} else if (article_headers)
		string_append_n(art->header, str, xstrlen(str)-1);	/* don't add ending \n */

	if (article_body)
		string_append_n(art->body, str, xstrlen(str)-1);	/* don't add ending \n */

	if (article_headers) {
		/* reencode headers */
		char *text, *org;
		char *line, *tmp;
		text = org = string_free(art->header, 0);

		/* join long headers fields */
		while ((tmp = xstrstr(text, "\n\t")) || (tmp = xstrstr(text, "\n "))) {
			memmove(tmp, tmp+1, xstrlen(tmp));
		}

		art->header = string_init(NULL);

		while ((line = split_line(&text))) {
			char *key, *value, *charset;
			char *charque, *encque, *endque;
			int i, vlen;

			if ((value = xstrstr(line, ": "))) {
				*value = '\0';
				value += 2;
			} else {
				string_append(art->header, line);
				string_append_c(art->header, '\n');
				continue;
			}

			string_append(art->header, line);
			string_append(art->header, ": ");

			key = line;

			/* Content-Transfer-Encoding */
			if (!xstrcmp(key, "Content-Transfer-Encoding")) { /* base64 || quoted-printable || 8bit || .... */
				if (!xstrncasecmp(value, "8bit", 4))		cte = ENCODING_8BIT;
				if (!xstrncasecmp(value, "base64", 6))		cte = ENCODING_BASE64;
				if (!xstrncasecmp(value, "quoted-printable", 16))	cte = ENCODING_QUOTEDPRINTABLE;
			}

			/* Content-Type */
			if (!xstrcmp(key, "Content-Type") && (tmp=xstrstr(value, "charset="))) {
				char *end = xstrchr(tmp, ';');
				if (!end)
					end = value + xstrlen(value) + 1;

				tmp += 8;
				if ('"' == *tmp) tmp++;
				if ('"' == end[-1]) end--;
				content_charset = xstrndup(tmp, end - tmp);

			}

			for (i=0, vlen=xstrlen(value); i<vlen; i++) {
				if	(!xstrncmp(&value[i], "=?", 2) &&			/* begins with =? */
					(charque = xstrchr(&value[i+2], '?')) &&		/* charset end with '?' */
					(encque = xstrchr(charque+1, '?')) &&			/* encoding end with '?' */
					(endque = xstrstr(encque+1, "?=")) &&			/* end */
					((toupper(*(encque-1)) == 'Q' || toupper(*(encque-1)) == 'B'))		/* valid encodings are: 'B' -- base64 && 'Q' -- quoted-printable */
					)
				{
					GString *decode = g_string_new("");
					char *recode;

					*charque = '\0';
					charset = value + i + 2;

					debug("RFC1522: header '%s:', encoding='%c', charset='%s'\n", key, *(encque-1), charset);

					i = (encque - value)+1;
					while (&value[i] != endque) {
						switch (toupper(*(encque-1))) {
							case 'Q':
								if (value[i] == '=' && value[i+1] && value[i+2]) {
									g_string_append_c(decode, hextochar(value[i+1]) * 16 | hextochar(value[i+2]));
									i += 2;
								} else	g_string_append_c(decode, value[i]);
								break;
							case 'B':
								*(endque) = 0;
								tmp = base64_decode(&value[i]);
								g_string_append(decode, tmp);
								xfree(tmp);
								i = (endque - value)-1;
								break;
						}
						i++;
					}
					i += 2;

					recode = ekg_recode_from(charset, decode->str);
					string_append(art->header, recode);
					g_free(recode);

					g_string_free(decode, TRUE);
				}
				if (i<vlen)
					string_append_c(art->header, value[i]);
			}

			string_append_c(art->header, '\n');
		}

		xfree(org);
	}

	if (article_body && article_headers) do {

		char *text;
		int i = 0;

		debug("content encoding type: %d, charset=%s\n", cte, content_charset?content_charset:"?");
		if (cte == ENCODING_UNKNOWN);

		text = string_free(art->body, 0);

		art->body = string_init(NULL);

		while (text[i]) {
			switch (cte) {
				case ENCODING_QUOTEDPRINTABLE:
					if (text[i] == '=' && text[i+1] == '\n') {
						i += 1;

					} else if (text[i] == '=' && text[i+1] && text[i+2]) {
						string_append_c(art->body, hextochar(text[i+1]) * 16 | hextochar(text[i+2]));
						i += 2;
					} else	string_append_c(art->body, text[i]);
					break;
				case ENCODING_BASE64:	/* XXX ? */
				case ENCODING_8BIT:
				default:
					string_append_c(art->body, text[i]);
			}
			i++;
		}
		xfree(text);

		if (content_charset) {
			char *recode = ekg_recode_from(content_charset, art->body->str);
			string_free(art->body, 1);
			art->body = string_init(recode);
			g_free(recode);
		}
	} while(0);


	{
		char *uid	= j->newsgroup		? j->newsgroup->uid	: NULL;
		char *sheaders	= NULL;
		char *headers	= article_headers	? art->header->str	: NULL;
		char *body	= article_body		? art->body->str	: NULL;
		char *artid	= (char *) ekg_itoa(art->artid);
		int modify	= 0;						/* XXX */

		query_emit(NULL, "nntp-message", &(s->uid), &uid, &sheaders, &headers, &artid, &(art->msgid), &body, &(art->new), &modify);
	}

	if (j->newsgroup) {
		j->newsgroup->state = NNTP_IDLE;
	} else debug("nntp_message_process() j->newsgroup == NULL!!!!\n");

	g_strfreev(tmpbody);
	return 0;
}

NNTP_HANDLER(nntp_auth_process) {
	nntp_private_t *j	= nntp_private(s);
	char *tmp;

	switch(code) {
		case 200:
		case 201:
			if (code == 200)	s->status = EKG_STATUS_AVAIL;
			else			s->status = EKG_STATUS_AWAY;

			tmp = s->descr;
			s->descr = xstrdup(str);
			xfree(tmp);

			if (!j->authed && session_get(s, "username"))
				nntp_write(s, "AUTHINFO USER %s\r\n", session_get(s, "username"));
			break;
		case 381:
			nntp_write(s, "AUTHINFO PASS %s\r\n", session_get(s, "password"));
			break;
		case 281:
			j->authed = 1;
			break;
		case 480:		/* XXX, auth required */
			break;
	}
	return 0;
}

NNTP_HANDLER(nntp_null_process) {
	debug("nntp_null_process() `%s`\n... %s\n", data, str);
	return 0;
}

NNTP_HANDLER(nntp_group_process) {
	nntp_private_t *j	= nntp_private(s);
	char **p = array_make(str, " ", 4, 1, 0);
	nntp_newsgroup_t *group;
	userlist_t *u;

	if (!p) return -1;
		/* 211 n f l s group selected */
	debug("nntp_group_process() str:%s p[0]: %s p[1]: %s p[2]: %s p[3]: %s p[4]: %s\n", str, p[0], p[1], p[2], p[3], p[4]);

	group		= nntp_newsgroup_find(s, p[3]);
	group->fart	= atoi(p[1]);
	group->lart	= atoi(p[2]);
	if (!group->cart) group->cart = group->lart;

	if ((u = userlist_find(s, group->uid))) {
		if (u->status == EKG_STATUS_AWAY) {
			nntp_set_descr(u, saprintf("First article: %d Last article: %d", group->fart, group->lart));
		}
	}

	j->newsgroup	= group;
	group->state	= NNTP_IDLE;

	g_strfreev(p);
	return 0;
}

NNTP_HANDLER(nntp_message_error) {
	nntp_private_t *j	= nntp_private(s);

	if (!j->newsgroup)	return -1;

	j->newsgroup->state	= NNTP_IDLE;
	return 0;
}

NNTP_HANDLER(nntp_group_error) {
	nntp_private_t *j	= nntp_private(s);

	if (!j->newsgroup) return -1;

	nntp_set_statusdescr(userlist_find(s, j->newsgroup->uid), EKG_STATUS_ERROR, saprintf("Generic error %d: %s", code, str));

	j->newsgroup->state	= NNTP_IDLE;
	j->newsgroup		= NULL;

	return 0;
}

NNTP_HANDLER(nntp_xover_process) {
	debug("xover: %s\n", str);
	return 0;
}

typedef	struct {
	int		num;
	nntp_handler	handler;
	int is_multi;
	void *data;
} nntp_handler_t;

nntp_handler_t nntp_handlers[] = {
	{100, nntp_help_process,	1, NULL},
	{200, nntp_auth_process,	0, NULL},
	{201, nntp_auth_process,	0, NULL},
	{281, nntp_auth_process,	0, NULL},
	{381, nntp_auth_process,	0, NULL},
	{480, nntp_auth_process,	0, NULL},

	{220, nntp_message_process,	1, NULL},
	{221, nntp_message_process,	1, NULL},
	{222, nntp_message_process,	1, NULL},
	{423, nntp_message_error,	0, NULL},

	{211, nntp_group_process,	0, NULL},
	{411, nntp_group_error,		0, NULL},

	{224, nntp_xover_process,	1, "xover"},

	{282, nntp_null_process,	1, "xgitle"},
	{-1, NULL,			0, NULL},
};

static void nntp_string_append(session_t *s, const char *str) {
	nntp_private_t *j	= nntp_private(s);
	string_t buf		= j->buf;

	string_append(buf, str);
	string_append_c(buf, '\n');
}

static nntp_handler_t *nntp_handler_find(int code) {
	int i;
	for (i = 0; nntp_handlers[i].num != -1; i++) {
		if (nntp_handlers[i].num == code) return &(nntp_handlers[i]);
	}
	return NULL;
}

static void nntp_parse_line(session_t *s, const char *line) {
	nntp_private_t *j = nntp_private(s);
	char **p;

	if (j->last_code != -1) {
		nntp_handler_t *handler = nntp_handler_find(j->last_code);

		if (!xstrcmp(line, ".")) {
			int res = -1;

			if (handler && handler->is_multi) res = handler->handler(s, j->last_code, j->buf->str, handler->data);

			debug("nntp_handlers() retval: %d code: %d\n", res, j->last_code);

			string_clear(j->buf);
			j->last_code = -1;
			if (res != -1) return;
		}

		if (handler && handler->is_multi) {
			nntp_string_append(s, line);
			return;
		}
	}

	if ((p = array_make(line, " ", 2, 1, 0)) && p[0] && atoi(p[0])) {
		int code = atoi(p[0]);

		nntp_handler_t *handler = nntp_handler_find(code);

		if (handler && handler->is_multi) {
			nntp_string_append(s, p[1]);
			j->last_code = code;
		} else if (handler) {
			handler->handler(s, code, p[1], handler->data);
			j->last_code = code;
		} else {
			debug("nntp_handle_stream() unhandled: %d (%s)\n", code, p[1]);
		}
	} else {
		debug("nntp_handle_stream() buf: %s (last: %d)\n", line, j->last_code);
	}
	g_strfreev(p);
}

static void nntp_handle_stream(connection_data_t *cd, GString *buffer) {
	session_t *s = ekg2_connection_get_session(cd);

	const char *found;

	while ((found = g_strstr_len(buffer->str, buffer->len, "\n"))) {
		int len = found - buffer->str + 1;
		gchar *line = g_strndup(buffer->str, len - 1);
		if ((len>1) && ('\r' == line[len-2]))
			line[len-2] = '\0';
debug_iorecv("%s\n", line);	// XXX temp
		nntp_parse_line(s, line);
		g_free(line);
		buffer = g_string_erase(buffer, 0, len);
	}
}

static void nntp_handle_connect(connection_data_t *cd) {
	session_t *s = ekg2_connection_get_session(cd);
	nntp_private_t *j = nntp_private(s);

	j->connecting = 0;
	protocol_connected_emit(s);
}

static COMMAND(nntp_command_disconnect)
{
	nntp_private_t	*j = nntp_private(session);

	if (!j->connecting && !session_connected_get(session)) {
		printq("not_connected", session_name(session));
		return -1;
	}

	if (session_connected_get(session))
		nntp_write(session, "QUIT\r\n");

	if (j->connecting)
		nntp_handle_disconnect(session, NULL, EKG_DISCONNECT_STOPPED);
	else
		nntp_handle_disconnect(session, NULL, EKG_DISCONNECT_USER);

	return 0;
}

static COMMAND(nntp_command_connect) {
	nntp_private_t *j = nntp_private(session);
	connection_data_t *cd;

	const char *server;
	int port = session_int_get(session, "port");

	if (j->connecting) {
		printq("during_connect", session_name(session));
		return -1;
	}
	if (session_connected_get(session)) {
		printq("already_connected", session_name(session));
		return -1;
	}

	if (!(server = session_get(session, "server"))) {
		printq("generic_error", "gdzie lecimy ziom ?! [/session server]");
		return -1;
	}

	if (port <= 0 || port > G_MAXUINT16)
		port = 119;		/* XXX default port */

	session->connecting = 1;
	printq("connecting", session_name(session));

	j->connection = cd = ekg2_connection_new(session, port);

	ekg2_connection_set_servers(cd, server);

	ekg2_connection_connect(cd,
			nntp_handle_connect,
			nntp_handle_stream,
			nntp_handle_disconnect);

	return 0;
}

static COMMAND(nntp_command_raw) {
	nntp_write(session, "%s\r\n", params[0]);
	return 0;
}

static COMMAND(nntp_command_nextprev) {
	nntp_private_t *j = nntp_private(session);
	int mode = session_int_get(session, "display_mode");

	if (!j->newsgroup) {
		printq("invalid_params", name, "???");	/* XXX */
		return -1;
	}
	if (!xstrcmp(name, "next"))	j->newsgroup->article++;
	else				j->newsgroup->article--;

	if (mode == 2)				nntp_write(session, "HEAD %d\r\n", j->newsgroup->article);
	else if (mode == 3 || mode == 4)	nntp_write(session, "ARTICLE %d\r\n", j->newsgroup->article);
	else if (mode == 0 || mode == -1)	;
	else					nntp_write(session, "BODY %d\r\n", j->newsgroup->article);

	return 0;
}

static COMMAND(nntp_command_get) {
	nntp_private_t *j = nntp_private(session);
	const char *comm = "ARTICLE";
	const char *group = NULL, *article = NULL;
	nntp_article_t *art = NULL;

	if (params[0] && params[1])	{ group = params[0]; article = params[1]; }
	else				{ article = params[0]; }

	if (!group && target)		group = target;
	if (!group && j->newsgroup)	group = j->newsgroup->uid;

	if (!article) {
		printq("not_enough_params", name);
		return -1;
	}

	if (!group) {
		/* no group */
		printq("not_enough_params", name);
		return -1;
	}

	if (!xstrncmp(group, "nntp:", 5)) group = group+5;	/* skip nntp: if exists */

	if (!j->newsgroup || xstrcmp(j->newsgroup->name, group)) {
/* zmienic grupe na target jesli != aktualnej .. */
		j->newsgroup = nntp_newsgroup_find(session, group);
		nntp_write(session, "GROUP %s\r\n", group);
	}

	j->newsgroup->article = atoi(article);

				art = nntp_article_find(j->newsgroup, j->newsgroup->article, NULL);
	if (!art->new)		art->new = 3;	/* turn on display flag. */
			/* XXX, wyswietlic artykul z kesza ? */

	if (!xstrcmp(name, "body")) comm = "BODY";

	nntp_write(session, "%s %s\r\n", comm, article);
	return 0;
}

static COMMAND(nntp_command_check) {
	extern void ekg_loop();

	nntp_private_t *j = nntp_private(session);
	userlist_t *ul;

	if (j->lock) {
		debug("nntp_command_check() j->lock = 1\n");	/* XXX, usleep ? czy please try again later ? */
		return 0;
	}
	j->lock = 1;

	for (ul = session->userlist; ul; ul = ul->next) {
		userlist_t *u		= ul;
		nntp_newsgroup_t *n;
		int i;

		if (params[0] && xstrcmp(params[0], u->uid)) continue;

		n = nntp_newsgroup_find(session, u->uid+5);

		nntp_set_statusdescr(u, EKG_STATUS_AWAY, xstrdup("Checking..."));

		j->newsgroup	= n;
		n->state	= NNTP_CHECKING;
		nntp_write(session, "GROUP %s\r\n", n->name);

		while (n->state == NNTP_CHECKING) ekg_loop();
		if (u->status == EKG_STATUS_ERROR) continue;

		if (n->cart == n->lart) {	/* nothing new */
			nntp_set_status(u, EKG_STATUS_DND);
			continue;
		}

		for (i = n->cart+1; i <= n->lart; i++) {
			int mode = session_int_get(session, "display_mode");

			n->state	= NNTP_DOWNLOADING;
			j->newsgroup	= n;
			nntp_set_descr(u, saprintf("Downloading %d article from %d", i, n->lart));

			if (mode == 2)				nntp_write(session, "HEAD %d\r\n", i);
			else if (mode == 3 || mode == 4)	nntp_write(session, "ARTICLE %d\r\n", i);
			else if (mode == 0 || mode == -1)	;
			else					nntp_write(session, "BODY %d\r\n", i);

			while (n->state == NNTP_DOWNLOADING) ekg_loop();
		}
		n->state		= NNTP_IDLE;

		nntp_set_statusdescr(u, EKG_STATUS_AVAIL, saprintf("%d new articles", n->lart - n->cart));
		j->newsgroup->cart = n->lart;

		if (params[0]) break;
	}
	j->lock = 0;
	return 0;
}

static COMMAND(nntp_command_subscribe) {
	userlist_t *u;

	if ((u = userlist_find(session, target))) {
		printq("nntp_exists_other", target, format_user(session, u->uid), session_name(session));
		return -1;
	}

	/* userlist_add() fails only when invalid uid was passed */
	// TODO: rss garbage
	if (target[0] == 'r' /* rss: */ || !(userlist_add(session, target, target))) {
		printq("invalid_session");
		return -1;
	}

	printq("nntp_added", target, session_name(session));
	query_emit(NULL, "userlist-refresh");
	return 0;
}

static COMMAND(nntp_command_unsubscribe) {
	userlist_t *u;
	if (!(u = userlist_find(session, target))) {
		printq("nntp_not_found", target);
		return -1;
	}

	printq("nntp_deleted", target, session_name(session));
	userlist_remove(session, u);
	query_emit(NULL, "userlist-refresh");
	return 0;
}

void *nntp_protocol_init() {
	nntp_private_t *p	= xmalloc(sizeof(nntp_private_t));
	p->buf			= string_init(NULL);
	return p;
}

void nntp_protocol_deinit(void *priv) {
}

void nntp_init() {
/*XXX,	:msg -- wysylanie wiadomosc na serwer... BE CAREFULL cause news aren't IM ;) */
	command_add(&nntp_plugin, ("nntp:connect"), "?",	nntp_command_connect, NNTP_ONLY, NULL);
	command_add(&nntp_plugin, ("nntp:disconnect"), "?", nntp_command_disconnect, NNTP_ONLY, NULL);

	command_add(&nntp_plugin, ("nntp:subscribe"), "!",	nntp_command_subscribe, NNTP_FLAGS_TARGET, NULL);
	command_add(&nntp_plugin, ("nntp:unsubscibe"), "!", nntp_command_unsubscribe, NNTP_FLAGS_TARGET, NULL);

	command_add(&nntp_plugin, ("nntp:check"), "u",	nntp_command_check, NNTP_FLAGS, NULL);

	command_add(&nntp_plugin, ("nntp:article"), "? ?",	nntp_command_get, NNTP_FLAGS, NULL);
	command_add(&nntp_plugin, ("nntp:body"),	"? ?",	nntp_command_get, NNTP_FLAGS, NULL);
	command_add(&nntp_plugin, ("nntp:raw"), "?",	nntp_command_raw, NNTP_FLAGS, NULL);

	command_add(&nntp_plugin, ("nntp:next"), "?",	nntp_command_nextprev, NNTP_FLAGS, NULL);
	command_add(&nntp_plugin, ("nntp:prev"), "?",	nntp_command_nextprev, NNTP_FLAGS, NULL);
}
