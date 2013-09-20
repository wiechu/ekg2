/* $Id$ */

/*
 *  (C) Copyright 2003-2005 Tomasz Torcz <zdzichu@irc.pl>
 *			    Leszek Krupiński <leafnode@wafel.com>
 *			    Adam Kuczyński <dredzik@ekg2.org>
 *			    Adam Mikuta <adamm@ekg2.org>
 *		       2012 Wiesław Ochmiński <wiechu@wiechu.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License Version
 *  2.1 as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "ekg2.h"

#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#include <netinet/in.h>
#endif

#if defined(__MINGW32__) || defined(__FreeBSD__) || defined(__sun)
#include <limits.h>
#endif

#include <sys/stat.h>
#include <sys/types.h>
#ifndef NO_POSIX_SYSTEM
#include <sys/mman.h>
#include <arpa/inet.h>
#endif

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "main.h"

PLUGIN_DEFINE(logs, PLUGIN_LOG, NULL);

#define EKG_RAW_LOGS_PATH "~/.ekg2/logs/__internal__/%P/%S/%u"

#define EKG_EMPTY_XML_LOG	"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" \
				"<!DOCTYPE ekg2log PUBLIC \"-//ekg2log//DTD ekg2log 1.0//EN\" " \
				"\"http://www.ekg2.org/DTD/ekg2log.dtd\">\n" \
				"<ekg2log xmlns=\"http://www.ekg2.org/DTD/\">\n" \
				"</ekg2log>\n"

	/* irssi style info messages */
#define IRSSI_LOG_EKG2_OPENED	"--- Log opened %a %b %d %H:%M:%S %Y"	/* defaultowy log_open_string irssi , jak cos to dodac zmienna... */
#define IRSSI_LOG_EKG2_CLOSED	"--- Log closed %a %b %d %H:%M:%S %Y"	/* defaultowy log_close_string irssi, jak cos to dodac zmienna... */
#define IRSSI_LOG_DAY_CHANGED	"--- Day changed %a %b %d %Y"		/* defaultowy log_day_changed irssi , jak cos to dodac zmienna... */

/*
 *	variables
 */

static GPtrArray *logs_logs = NULL;

static int open_files_count = 0;

static int config_logs_log;
static int config_logs_log_raw;
static int config_logs_log_ignored;		// XXX unused
static int config_logs_log_status;
static int config_logs_remind_number = 0;
static int config_logs_max_files = 7;
static char *config_logs_path;
static char *config_logs_timestamp;
static gchar *config_logs_encoding;

/*
 * log_escape()
 *
 * jeśli trzeba, eskejpuje tekst do logów.
 *
 *  - str - tekst.
 *
 * zaalokowany bufor.
 */
static char *log_escape(const char *str)
{
	const char *p;
	char *res, *q;
	int len, esclen;

	if (!str)
		return NULL;

	len = esclen = strlen(str);

	for (p = str; *p; p++) {
		if (*p == '"' || *p == '\'' || *p == '\r' || *p == '\n' || *p == ',' || *p == '\\')
			esclen++;
	}

	if (len == esclen)
		return g_strdup(str);

	q = res = xmalloc(esclen + 3);

	*q++ = '"';

	for (p = str; *p; p++, q++) {
		if (*p == '\\' || *p == '"' || *p == '\'') {
			*q++ = '\\';
			*q = *p;
		} else if (*p == '\n') {
			*q++ = '\\';
			*q = 'n';
		} else if (*p == '\r') {
			*q++ = '\\';
			*q = 'r';
		} else
			*q = *p;
	}
	*q++ = '"';
	*q = 0;

	return res;
}

static char *fstring_reverse(fstring_t *fstr) {
	const char *str;
	const fstr_attr_t *attr;
	string_t asc;
	int i;

	if (!fstr)
		return NULL;

	attr = fstr->attr;
	str = fstr->str;

	if (!attr || !str)
		return NULL;

	asc = string_init(NULL);

	for (i = 0; str[i]; i++) {
#define prev	attr[i-1]
#define cur	attr[i]
		int reset = 0;

		if (i) {
			if (!(cur & FSTR_BOLD) && (prev & FSTR_BOLD))		reset = 1;
			if (!(cur & FSTR_BLINK) && (prev & FSTR_BLINK))		reset = 1;
			if (!(cur & FSTR_UNDERLINE) && (prev & FSTR_UNDERLINE))	reset = 1;
			if (!(cur & FSTR_REVERSE) && (prev & FSTR_REVERSE))	reset = 1;
			if ((cur & FSTR_NORMAL) && !(prev & FSTR_NORMAL))	reset = 1;	/* colors disappear */

			if (reset)
				string_append(asc, "%n");
		} else
			reset = 1;

	/* attr */
		if ((cur & FSTR_BLINK) &&	(reset || !(prev & FSTR_BLINK)))	string_append(asc, "%i");
//		if ((cur & FSTR_UNDERLINE) &&	(reset || !(prev & FSTR_UNDERLINE)))	string_append(asc, "%");
//		if ((cur & FSTR_REVERSE) &&	(reset || !(prev & FSTR_REVERSE)))	string_append(asc, "%");

		if (!(cur & FSTR_NORMAL)) {
		/* background color XXX */
#define BGCOLOR(x)	-1
			if (0 && ((reset || BGCOLOR(cur) != BGCOLOR(prev)))) {
				string_append_c(asc, '%');
				switch (BGCOLOR(cur)) {
					case (0): string_append_c(asc, 'l'); break;
					case (1): string_append_c(asc, 's'); break;
					case (2): string_append_c(asc, 'h'); break;
					case (3): string_append_c(asc, 'z'); break;
					case (4): string_append_c(asc, 'e'); break;
					case (5): string_append_c(asc, 'q'); break;
					case (6): string_append_c(asc, 'd'); break;
					case (7): string_append_c(asc, 'x'); break;
				}
			}
#undef BGCOLOR

		/* foreground color */
#define FGCOLOR(x)	((!(x & FSTR_NORMAL)) ? (x & FSTR_FOREMASK) : -1)
			if (((reset || FGCOLOR(cur) != FGCOLOR(prev)) || (i && (prev & FSTR_BOLD) != (cur & FSTR_BOLD)))) {
				string_append_c(asc, '%');
				switch ((cur & FSTR_FOREMASK)) {
					case (0): string_append_c(asc, (cur & FSTR_BOLD) ? 'K' : 'k'); break;
					case (1): string_append_c(asc, (cur & FSTR_BOLD) ? 'R' : 'r'); break;
					case (2): string_append_c(asc, (cur & FSTR_BOLD) ? 'G' : 'g'); break;
					case (3): string_append_c(asc, (cur & FSTR_BOLD) ? 'Y' : 'y'); break;
					case (4): string_append_c(asc, (cur & FSTR_BOLD) ? 'B' : 'b'); break;
					case (5): string_append_c(asc, (cur & FSTR_BOLD) ? 'M' : 'm'); break; /* | fioletowy	 | %m/%p  | %M/%P | %q	| */
					case (6): string_append_c(asc, (cur & FSTR_BOLD) ? 'C' : 'c'); break;
					case (7): string_append_c(asc, (cur & FSTR_BOLD) ? 'W' : 'w'); break;
				}
			}
#undef FGCOLOR
		} else {	/* no color */
			if ((cur & FSTR_BOLD) && (reset || !(prev & FSTR_BOLD)))
				string_append(asc, "%T");
		}

	/* str */
		if (str[i] == '%' || str[i] == '\\')
			string_append_c(asc, '\\');
		string_append_c(asc, str[i]);
	}

/* reset, and return. */
	string_append(asc, "%n");
	return string_free(asc, 0);

#undef prev
#undef cur
}

/*
 * zwraca format
 * w zaleznosci od ustawien log_format w sesji i log:logs
 */

static int logs_log_format(session_t *s) {
	const char *log_formats;

	if (config_logs_log == LOG_FORMAT_NONE)
		return LOG_FORMAT_NONE;

	if (!s || !(log_formats = session_get(s, "log_formats")))
		return LOG_FORMAT_NONE;

	if (xstrstr(log_formats, "irssi"))
		return LOG_FORMAT_IRSSI;
	if (config_logs_log == LOG_FORMAT_SIMPLE && xstrstr(log_formats, "simple"))
		return LOG_FORMAT_SIMPLE;
	if (config_logs_log == LOG_FORMAT_XML && xstrstr(log_formats, "xml"))
		return LOG_FORMAT_XML;

	return LOG_FORMAT_NONE;
}

/*
 * zwraca na przemian jeden z dwóch statycznych buforów, więc w obrębie
 * jednego wyrażenia można wywołać tę funkcję dwukrotnie.
 */
/* w sumie starczylby 1 statyczny bufor ... */
static const char *prepare_timestamp_format(const char *format, time_t t) {
	static char buf[2][100];
	struct tm *tm = localtime(&t);
	static int i = 0;

	if (!format)
		return ekg_itoa(t);

	if (!format[0])
		return "";

	i = i % 2;

	if (!strftime(buf[i], sizeof(buf[0]), format, tm))
		return "TOOLONG";

	return buf[i++];
}

/*
 * przygotowanie nazwy pliku z rozszerzeniem
 * %S - sesja nasza
 * %u - użytkownik (uid), z którym piszemy
 * %U - użytkownik (nick)   -||-
 * %Y, %M, %D - rok, miesiąc, dzień
 * zwraca ścieżkę, która należy ręcznie zwolnić przez xfree()
 */
static char *logs_prepare_fname(logs_log_t *log) {
	session_t *s;
	const char *logs_path;
	struct tm *tm = NULL;
	string_t buf;
	time_t sent = time(NULL);

	g_return_val_if_fail(log != NULL, NULL);
	g_return_val_if_fail(log->format != LOG_FORMAT_NONE, NULL);

	logs_path = (LOG_FORMAT_RAW == log->format) ? EKG_RAW_LOGS_PATH : config_logs_path;

	g_return_val_if_fail(logs_path != NULL, NULL);

	buf = g_string_new(NULL);
	s = session_find(log->session);

	while (*logs_path) {
		if (*logs_path == '%' && *(logs_path+1) != '\0') {
			char *append = NULL;
			logs_path++;
			switch (*logs_path) {
				case 'S':	append = g_strdup(s ? s->uid : "_null_");
						break;
				case 'P':	append = g_strdup(config_profile ? config_profile : "_default_");
						break;
				case 'U':
				case 'u':	append = g_strdup(*logs_path=='u' ? log->uid : get_nickname(s, log->uid));
						if (!append)
							append = g_strdup(log->uid);
						break;
				case 'Y':	if (!tm) tm = localtime(&sent);
						append = g_strdup_printf("%4d", tm->tm_year+1900);
						break;
				case 'M':	if (!tm) tm = localtime(&sent);
						append = g_strdup_printf("%02d", tm->tm_mon+1);
						break;
				case 'D':	if (!tm) tm = localtime(&sent);
						append = g_strdup_printf("%02d", tm->tm_mday);
						break;
				default:	g_string_append_c(buf, *logs_path);
			};
			if (append) {
				// XXX g_uri_escape_string( , , allow_utf8) ?
				char *tmp = g_uri_escape_string(append, G_URI_RESERVED_CHARS_ALLOWED_IN_PATH_ELEMENT, TRUE);
				g_string_append(buf, tmp);
				g_free(tmp);
				g_free(append);
			}

		} else if (*logs_path == '~' && (*(logs_path+1) == '/' || *(logs_path+1) == '\0')) {
			g_string_append(buf, home_dir);
		} else
			string_append_c(buf, *logs_path);
		logs_path++;
	};

	switch (log->format) {
		case LOG_FORMAT_RAW:	g_string_append(buf, ".raw");	break;
		case LOG_FORMAT_SIMPLE:	g_string_append(buf, ".txt");	break;
		case LOG_FORMAT_IRSSI:	g_string_append(buf, ".log");	break;
		case LOG_FORMAT_XML:	g_string_append(buf, ".xml");	break;
	}

	// TODO sanityzacja sciezki - wywalic "../",
	xstrtr(buf->str, ' ', '_');

	return g_string_free(buf, FALSE);
}

static void logs_log_close(logs_log_t *ll) {

	if (!ll || !ll->file)
		return;

	fclose(ll->file);
	ll->file = NULL;
	open_files_count--;

	return;
}

static void logs_log_destroy(gpointer data) {
	logs_log_t *log = data;

	g_return_if_fail(log != NULL);

	if ((LOG_FORMAT_IRSSI == log->format) && xstrlen(IRSSI_LOG_EKG2_CLOSED)) {
		logs_open_file(log);
		log->daychanged = 0;
		logs_irssi_sysmsg(log, prepare_timestamp_format(IRSSI_LOG_EKG2_CLOSED, time(NULL)));
	}

	logs_log_close(log);

	debug_function("logs_log_destroy(%d) %s\n", logs_logs->len, log->fname);

	g_free(log->fname);
	g_free(log->session);
	g_free(log->uid);

	g_free(log);
}

/*
 * otwarcie pliku do zapisu/odczytu
 * tworzy wszystkie katalogi po drodze, jeśli nie istnieją i mkdir =1
 * ff - xml 2 || irssi 3 || simple 1
 * zwraca numer deskryptora bądź NULL
 */
static int logs_open_file(logs_log_t *ll) {

	g_return_val_if_fail(ll != NULL, -1);

	if (ll->file)
		return fseek(ll->file, 0, SEEK_END);

	g_return_val_if_fail(ll->fname != NULL, -1);
	g_return_val_if_fail(ll->format != LOG_FORMAT_NONE, -1);

// XXX temp
debug("[logs] opening log file %s ff:%d\n", __(ll->fname), ll->format);

	if (!g_file_test(ll->fname, G_FILE_TEST_IS_REGULAR) && mkdir_recursive(ll->fname, 0)) {
		print("directory_cant_create", ll->fname, strerror(errno));
		return -1;
	}

	if (!(ll->file = fopen(ll->fname, "a+")))
		return -1;

	if (ll->format == LOG_FORMAT_XML) {
		/* prepare xml file */
		fputs(EKG_EMPTY_XML_LOG, ll->file);
	}

	// move ll on top
	if (ll != g_ptr_array_index(logs_logs, logs_logs->len - 1)) {
		g_ptr_array_set_free_func(logs_logs, NULL);
		g_ptr_array_remove(logs_logs, ll);
		g_ptr_array_add(logs_logs, ll);
		g_ptr_array_set_free_func(logs_logs, logs_log_destroy);
	}

	open_files_count++;
	logs_open_files_check();

	return fseek(ll->file, 0, SEEK_END);
}


static logs_log_t *logs_log_find(const char *session, const char *uid, gboolean raw) {
	int i;

	for (i = logs_logs->len - 1; i >=0; i--) {
		logs_log_t *ll = g_ptr_array_index(logs_logs, i);

		if (raw ^ (LOG_FORMAT_RAW == ll->format)) continue;
		if (xstrcmp(ll->uid, uid)) continue;
		if (ll->session && xstrcmp(ll->session, session)) continue;

		return ll;
	}

	return NULL;

}

static logs_log_t *logs_log_new(const char *session, const char *target, gboolean raw) {
	logs_log_t *ll;
	log_format_t format;
	char *uid, *tmp;

	if (LOG_FORMAT_NONE == (format = raw ? LOG_FORMAT_RAW : logs_log_format(session_find(session))))
		return NULL;

	if (!(uid = g_strdup(get_uid_any(session_find(session), target))))
		uid = g_strdup(target);
	if ((tmp = xstrchr(uid, '/')))
		*tmp = '\0';		// strip resource

	ll = logs_log_find(session, uid, raw);

	if (ll) {
		g_free(uid);
		return ll;
	}

	// Create new
	ll = xmalloc(sizeof(logs_log_t));
	ll->session = g_strdup(session);
	ll->uid = uid;
	ll->format = format;
	ll->fname = logs_prepare_fname(ll);

	g_ptr_array_add(logs_logs, ll);

	if (ll->format == LOG_FORMAT_IRSSI && xstrlen(IRSSI_LOG_EKG2_OPENED)) {
		logs_open_file(ll);
		logs_irssi_sysmsg(ll, prepare_timestamp_format(IRSSI_LOG_EKG2_OPENED, time(NULL)));
	}

	debug("[logs] log_new s=%s uid=%s ff=%d logs_log_t %x\n", __(session), __(uid), ll->format, ll);

	return ll;
}

static logs_log_t *logs_log_open(const char *session, const char *uid, gboolean raw) {
	logs_log_t *ll;

	if (!(ll = logs_log_new(session, uid, raw)))
		return NULL;

	logs_open_file(ll);

	if (ll->file)
		return ll;

	debug_error("logs_log_open(%s, %u, %d) - Can't open %s ff=%d\n", session, uid, raw, ll->fname, ll->format);

	g_ptr_array_remove(logs_logs, ll);

	return NULL;
}

static void logs_open_files_check() {
	int i;

	if (config_logs_max_files <= 0)
		return;

	for (i=0; (open_files_count > config_logs_max_files) && (i < logs_logs->len); i++) {
		logs_log_close(g_ptr_array_index(logs_logs, i));
	}
}

static void logs_log_reopen(logs_log_t *ll) {
	char *session = g_strdup(ll->session);
	char *uid = g_strdup(ll->uid);
	char *oldfn = g_strdup(ll->fname);

	g_ptr_array_remove(logs_logs, ll);

	ll = logs_log_new(session, uid, FALSE);

	debug_function("logs_log_reopen() %s => %s\n", oldfn, ll?ll->fname:"");

	g_free(session);
	g_free(uid);
	g_free(oldfn);
}

/*
 * logs_day_changed()
 *
 * "day-changed" handler
 */
static QUERY(logs_day_changed) {
	struct tm *now	= *(va_arg(ap, struct tm**));
	struct tm *old	= *(va_arg(ap, struct tm**));
	int i;
	gboolean dfmt;

	if (!logs_logs)
		return 0;

	debug_function("logs_day_changed()\n");

	dfmt =	((now->tm_year != old->tm_year) && xstrstr(config_logs_path, "%Y")) ||
		((now->tm_mon != old->tm_mon) && xstrstr(config_logs_path, "%M")) ||
		((now->tm_mday != old->tm_mday) && xstrstr(config_logs_path, "%D"));

	for (i = logs_logs->len - 1; i >= 0; i--) {
		logs_log_t *ll = g_ptr_array_index(logs_logs, i);
		if (LOG_FORMAT_RAW == ll->format) continue;
		if (dfmt)
			logs_log_reopen(ll);
		else
			ll->daychanged = 1;
	}

	return 0;
}

/*
 * logs_session_var_changed()
 *
 * "session-variable-changed" handler
 */
static QUERY(logs_session_var_changed) {
	char *session	= *(va_arg(ap, char**));
	char *var	= *(va_arg(ap, char**));
	int i;

	if (!logs_logs || (0 == logs_logs->len))
		return 0;

	if (!xstrcmp(var, "log_formats")) {
		session_t *s = session_find(session);
		int newformat = logs_log_format(s);

		debug_function("logs_session_var_changed() s=%s, %s=%s\n", session, var, session_get(s, var));

		for (i = logs_logs->len - 1; 0 <= i; i--) {
			logs_log_t *ll = g_ptr_array_index(logs_logs, i);
			if (LOG_FORMAT_RAW == ll->format) continue;
			if (xstrcmp(ll->session, session)) continue;
			if (ll->format != newformat)
				logs_log_reopen(ll);
		}
	}

	return 0;
}

/*
 * plugin's variable handler
 *
 */
static void logs_variable_changed(const char *var) {
	int i;

	g_return_if_fail(logs_logs != NULL);

	if (!xstrcmp(var, "logs:max_open_files")) {
		logs_open_files_check();
	} else if (!xstrcmp(var, "logs:log_raw") && !config_logs_log_raw) {
		// remove raw logs
		for (i = logs_logs->len - 1; 0 <= i; i--) {
			logs_log_t *ll = g_ptr_array_index(logs_logs, i);
			if (LOG_FORMAT_RAW == ll->format)
				g_ptr_array_remove(logs_logs, ll);
		}
	} else if (!xstrcmp(var, "logs:path") || !xstrcmp(var, "logs:log")) {
		for (i = logs_logs->len - 1; 0 <= i; i--) {
			logs_log_t *ll = g_ptr_array_index(logs_logs, i);
			char *tmp;
			if (LOG_FORMAT_RAW == ll->format) continue;
			if (!config_logs_path || (LOG_FORMAT_NONE == config_logs_log)) {
				g_ptr_array_remove(logs_logs, ll);
				continue;
			}

			tmp = logs_prepare_fname(ll);
			if (xstrcmp(tmp, ll->fname)) {
				// new file name; reopen
				logs_log_reopen(ll);
			}
			g_free(tmp);
		}
	} else if (!xstrcmp(var, "logs:log_status") && !config_logs_log_status) {
		for (i = logs_logs->len - 1; 0 <= i; i--) {
			logs_log_t *ll = g_ptr_array_index(logs_logs, i);
			if (LOG_FORMAT_RAW == ll->format) continue;
			if (!window_find_s(session_find(ll->session), ll->uid))
				g_ptr_array_remove(logs_logs, ll);
		}
	}
}

static int logs_print_window(session_t *s, window_t *w, const char *line, time_t ts) {
	static plugin_t *ui_plugin = NULL;

	fstring_t *fstr;

	/* it's enough to look for ui_plugin once */
	if (!ui_plugin) ui_plugin = plugin_find(("ncurses"));
	if (!ui_plugin) ui_plugin = plugin_find(("gtk"));
	if (!ui_plugin) {
		debug_error("WARN logs_print_window() called but neither ncurses plugin nor gtk found\n");
		return -1;
	}

	fstr = fstring_new_format(line);
	fstr->ts = ts;

	query_emit(ui_plugin, "ui-window-print", &w, &fstr);
	fstring_free(fstr);
	return 0;
}

static void logs_buffer_raw_display(window_t *w) {
	char *line, **lines;
	logs_log_t *ll;
	int i, j, n, all = (config_logs_remind_number <= 0);

	if (!w || !w->session)
		return;

	if ((WINDOW_STATUS_ID == w->id) || (WINDOW_CONTACTS_ID == w->id) || (WINDOW_LASTLOG_ID ==w->id ))
		return;

	if (!(ll = logs_log_open(session_uid_get(w->session), w->target, TRUE)))
		return;

	if (!all)
		lines = g_new0(char *, config_logs_remind_number + 1);

	// read log
	n = 0;
	fseek(ll->file, 0, SEEK_SET);
	while ((line = read_file(ll->file, 0))) {
		ekg_fix_utf8(line);
		if (all) {
			time_t t = g_ascii_strtoll(line, &line, 10);
			if (t>0 && *line == ' ') line++;
			logs_print_window(w->session, w, line, t);
		} else {
			j = n % config_logs_remind_number;
			g_free(lines[j]);
			lines[j] = g_strdup(line);
			n++;
		}
	}

	if (all) {
		query_emit(NULL, "ui-window-refresh");
		return;
	}

	ftruncate(fileno(ll->file), 0);

	// display and rewrite log
	w->lock++;
	for (i=0; i < config_logs_remind_number; i++, n++) {
		time_t t;
		j = n % config_logs_remind_number;
		if (!lines[j])
			continue;
		fputs(lines[j], ll->file);
		fputc('\n', ll->file);

		t = g_ascii_strtoll(lines[j], &line, 10);
		if (t>0 && *line == ' ') line++;
		logs_print_window(w->session, w, line, t);
	}
	w->lock--;

	g_strfreev(lines);

	query_emit(NULL, "ui-window-refresh");

}

static const char *logs_class2str(msgclass_t class) {
	switch (class) {
		case EKG_MSGCLASS_MESSAGE	: return "msgrecv";
		case EKG_MSGCLASS_CHAT		: return "chatrecv";
		case EKG_MSGCLASS_SENT		: return "msgsend";
		case EKG_MSGCLASS_SENT_CHAT	: return "chatsend";
		case EKG_MSGCLASS_SYSTEM	: return "msgsystem";
		case EKG_MSGCLASS_PRIV_STATUS	: return "status";
		default				: return "chatrecv";
	};
}

/*
 * zapis w formacie znanym z ekg1
 * typ,uid,nickname,timestamp,{timestamp wyslania dla odleglych}, text
 */

static void logs_simple(FILE *file, const char *session, const char *uid, const char *text, time_t sent, msgclass_t class, const char *status) {
	char *textcopy;
	const char *timestamp = prepare_timestamp_format(config_logs_timestamp, time(0));

	session_t *s = session_find((const char*)session);
	const char *gotten_uid = get_uid(s, uid);
	const char *gotten_nickname = get_nickname(s, uid);

	const gchar *logsenc = config_logs_encoding ? config_logs_encoding : console_charset;
	GString *tmp;

	if (!file)
		return;
	textcopy = log_escape(text);

	if (!gotten_uid)	gotten_uid = uid;
	if (!gotten_nickname)	gotten_nickname = uid;

	fputs(logs_class2str(class), file);
	fputc(',', file);

	/*
	 * chatsend,<numer>,<nick>,<czas>,<treść>
	 * chatrecv,<numer>,<nick>,<czas_otrzymania>,<czas_nadania>,<treść>
	 * status,<numer>,<nick>,[<ip>],<time>,<status>,<descr>
	 */

	tmp = g_string_new(gotten_uid);
	ekg_recode_gstring_to(logsenc, tmp);
	fputs(tmp->str, file);      fputc(',', file);
	g_string_assign(tmp, gotten_nickname);
	ekg_recode_gstring_to(logsenc, tmp);
	fputs(tmp->str, file); fputc(',', file);
	if (class == EKG_MSGCLASS_PRIV_STATUS) {
		userlist_t *u = userlist_find(s, gotten_uid);
		int __ip = u ? user_private_item_get_int(u, "ip") : INADDR_NONE;

		fputs(inet_ntoa(*((struct in_addr*) &__ip)), file);
		fputc(':', file);
		fputs(ekg_itoa(u ? user_private_item_get_int(u, "port") : 0), file);
		fputc(',', file);
	}

	fputs(timestamp, file); fputc(',', file);

	if (class == EKG_MSGCLASS_MESSAGE || class == EKG_MSGCLASS_CHAT) {
		const char *senttimestamp = prepare_timestamp_format(config_logs_timestamp, sent);
		fputs(senttimestamp, file);
		fputc(',', file);
	} else if (class == EKG_MSGCLASS_PRIV_STATUS) {
		fputs(status, file);
		fputc(',', file);
	}
	if (textcopy) {
		g_string_assign(tmp, textcopy);
		ekg_recode_gstring_to(logsenc, tmp);
		fputs(tmp->str, file);
	}
	fputs("\n", file);

	xfree(textcopy);
	g_string_free(tmp, TRUE);
	fflush(file);
}

/*
 * zapis w formacie xml
 */

static void logs_xml(FILE *file, const char *session, const char *uid, const char *text, time_t sent, msgclass_t class) {
	session_t *s;
	char *textcopy;
	const char *timestamp = prepare_timestamp_format(config_logs_timestamp, time(NULL));
/*	const char *senttimestamp = prepare_timestamp_format(config_logs_timestamp, sent); */
	char *gotten_uid, *gotten_nickname;
	const char *tmp;

	if (!file)
		return;

	textcopy	= xml_escape( text);

	s = session_find((const char*)session);
	gotten_uid	= xml_escape( (tmp = get_uid(s, uid))		? tmp : uid);
	gotten_nickname = xml_escape( (tmp = get_nickname(s, uid))	? tmp : uid);

	fseek(file, -11, SEEK_END); /* wracamy przed </ekg2log> */

	/*
	 * <message class="chatsend">
	 * <time>
	 *	<sent>...</sent>
	 *	<received>...</received>
	 * </time>
	 * <sender>
	 *	<uid>...</uid>
	 *	<nick>...</nick>
	 * </sender>
	 * <body>
	 *	(#PCDATA)
	 * </body>
	 * </message>
	 */

	fputs("<message class=\"",file);

	fputs(logs_class2str(class), file);

	fputs("\">\n", file);

	fputs("\t<time>\n", file);
	fputs("\t\t<received>", file); fputs(timestamp, file); fputs("</received>\n", file);
	if (class == EKG_MSGCLASS_MESSAGE || class == EKG_MSGCLASS_CHAT) {
		fputs("\t\t<sent>", file); fputs(timestamp, file); fputs("</sent>\n", file);
	}
	fputs("\t</time>\n", file);

	fputs("\t<sender>\n", file);
	fputs("\t\t<uid>", file);   fputs(gotten_uid, file);	   fputs("</uid>\n", file);
	fputs("\t\t<nick>", file);  fputs(gotten_nickname, file);  fputs("</nick>\n", file);
	fputs("\t</sender>\n", file);

	fputs("\t<body>\n", file);
	if (textcopy) fputs(textcopy, file);
	fputs("\t</body>\n", file);

	fputs("</message>\n", file);
	fputs("</ekg2log>\n", file);

	xfree(textcopy);
	xfree(gotten_uid);
	xfree(gotten_nickname);
	fflush(file);
}


/*
 * zapis w formacie gaim'a
 */

#if 0
static void logs_gaim()
{
}
#endif

/*
 * write to file like irssi do.
 */

static void logs_irssi(logs_log_t *log, const char *session, const char *uid, const char *text, time_t sent, msgclass_t class) {
	const char *nuid = NULL;	/* get_nickname(session_find(session), uid) */
	gchar *tmp, *enc;

	g_return_if_fail(log != NULL);
	g_return_if_fail(log->file != NULL);

	if (log->daychanged) {
		log->daychanged = 0;
		logs_irssi_sysmsg(log, prepare_timestamp_format(IRSSI_LOG_DAY_CHANGED, time(NULL)));
	}

	switch (class) {
		case EKG_MSGCLASS_PRIV_STATUS:
		{
			userlist_t *u = userlist_find(session_find(session), uid);
			int __ip = u ? user_private_item_get_int(u, "ip") : INADDR_NONE;

			tmp = g_strdup_printf("%s * %s reports status: %s [~notirc@%s:%s] /* {status} */\n", prepare_timestamp_format(config_logs_timestamp, sent), nuid ? nuid : __(uid), __(text), inet_ntoa(*((struct in_addr*) &__ip)), ekg_itoa(u ? user_private_item_get_int(u, "port") : 0));
			break;
		}

		case EKG_MSGCLASS_SYSTEM: /* other messages like session started, session closed and so on */
			tmp = g_strdup_printf("%s\n", __(text));
			break;

		case EKG_MSGCLASS_MESSAGE:	/* just normal message */
			tmp = g_strdup_printf("%s <%s> %s\n", prepare_timestamp_format(config_logs_timestamp, sent), nuid ? nuid : __(uid), __(text));
			break;

		default: /* everythink else */
			debug("[LOGS_IRSSI] UTYPE = %d\n", class);
			return; /* to avoid flushisk file */
	}
	enc = ekg_recode_to(config_logs_encoding, tmp);
	fputs(enc, log->file);
	g_free(tmp);
	g_free(enc);
	fflush(log->file);
}

static void logs_irssi_sysmsg(logs_log_t *log, const char *text) {
	logs_irssi(log, NULL, NULL, text, 0, EKG_MSGCLASS_SYSTEM);
}


/**
 * glowny handler
 */

static QUERY(logs_handler) {
	char *session	= *(va_arg(ap, char**));
	char *uid	= *(va_arg(ap, char**));
	char **rcpts	= *(va_arg(ap, char***));
	char *text	= *(va_arg(ap, char**));
		guint32 **UNUSED(format)	= va_arg(ap, guint32**);
	time_t	 sent	= *(va_arg(ap, time_t*));
	int  class	= *(va_arg(ap, int*));
		char **UNUSED(seq)		= va_arg(ap, char**);

	session_t *s = session_find(session); // session pointer
	logs_log_t *ll;
	char *conf_uid = NULL;		/* conference-uid */
	char *target_uid;

	/* olewamy jesli to irc i ma formatke irssi like, czekajac na irc-protocol-message */
	if (session_check(s, 0, "irc") && logs_log_format(s) == LOG_FORMAT_IRSSI)
		return 0;
	if (ignored_check(s, uid) & IGNORE_LOG)
		return 0;

	class &= ~(EKG_NO_THEMEBIT | EKG_MSGCLASS_NOT2US);

	target_uid = (class >= EKG_MSGCLASS_SENT) ? rcpts[0] : uid;

	/* XXX, think more about conferences-logging */
	if (class < EKG_MSGCLASS_SENT) {
		int recipients_count = g_strv_length((char **) rcpts);

		if (recipients_count > 0) {
			struct conference *c;

			if ((c = conference_find_by_uids(s, uid, (const char **) rcpts, recipients_count, 0)))
				conf_uid = c->name;
			else
				debug_error("logs_handler() smth strange happen (c == NULL) && recipients_count > 0 [%d]\n", recipients_count);
		}
	}

	if (!(ll = logs_log_open(session, conf_uid ? conf_uid : target_uid, FALSE)))
		return 0;

	/* uid = uid | target_uid ? */

	switch (ll->format) {
		case LOG_FORMAT_SIMPLE:
			logs_simple(ll->file, session, target_uid, text, sent, class, (char*)NULL);
			break;

		case LOG_FORMAT_XML:
			logs_xml(ll->file, session, uid, text, sent, class);
			break;

		case LOG_FORMAT_IRSSI:
			logs_irssi(ll, session, uid, text, sent, EKG_MSGCLASS_MESSAGE);
			break;
	}
	return 0;
}

/*
 * status handler
 */

static QUERY(logs_status_handler) {
	char *session	= *(va_arg(ap, char**));
	char *uid	= *(va_arg(ap, char**));
	int status	= *(va_arg(ap, int*));
	char *descr	= *(va_arg(ap, char**));

	logs_log_t *ll;

	/* joiny, party	ircowe jakies inne query. lub zrobic to w pluginie irc... ? */
	/*
	   if (session_check(s, 0, "irc") && !xstrcmp(logs_log_format(s), "irssi"))
	   return 0;
	   */
	if (config_logs_log_status <= 0)
		return 0;

	if (ignored_check(session_find(session), uid) & IGNORE_LOG)
		return 0;

	if (!(ll = logs_log_open(session, uid, FALSE)))
		return 0;

	if (!descr)
		descr = "";

	switch (ll->format) {
		case LOG_FORMAT_SIMPLE:
		{
			logs_simple(ll->file, session, uid, descr, time(NULL), EKG_MSGCLASS_PRIV_STATUS, ekg_status_string(status, 0));
			break;
		}

		case LOG_FORMAT_XML:
		{
			// logs_xml(ll->file, session, uid, descr, time(NULL), EKG_MSGCLASS_PRIV_STATUS, status);
			break;
		}

		case LOG_FORMAT_IRSSI:
		{
			char *_what = saprintf("%s (%s)", descr, __(ekg_status_string(status, 0)));
			logs_irssi(ll, session, uid, _what, time(NULL), EKG_MSGCLASS_PRIV_STATUS);
			xfree(_what);
			break;
		}
	}
	return 0;
}

static QUERY(logs_handler_irc) {
	char *session	= *(va_arg(ap, char**));
	char *uid	= *(va_arg(ap, char**));
	char *text	= *(va_arg(ap, char**));
		int  *UNUSED(isour)	= va_arg(ap, int*);
		int  *UNUSED(foryou)	= va_arg(ap, int*);
		int  *UNUSED(priv_data)	= va_arg(ap, int*);
	char *channame	= *(va_arg(ap, char**));
	logs_log_t *ll;
	session_t *s = session_find(session);

	if (ignored_check(s, uid) & IGNORE_LOG)
		return 0;

	if (!(ll = logs_log_open(session, channame, FALSE)))
		return 0;

	switch (ll->format) {
		case LOG_FORMAT_IRSSI:
			logs_irssi(ll, session, uid, text, time(NULL), EKG_MSGCLASS_MESSAGE);
			break;
	}
	return 0;
}

QUERY(logs_handler_raw) {
	window_t *w	= *(va_arg(ap, window_t **));
	fstring_t *line = *(va_arg(ap, fstring_t **));
	logs_log_t *ll;
	char *str;

	if (!config_logs_log_raw) return 0;
	if (!w || !line) return 0;
	// XXX
	if (w->id == WINDOW_DEBUG_ID || w->id == WINDOW_STATUS_ID || w->id == WINDOW_CONTACTS_ID) return 0;

	if (!(ll = logs_log_open(session_uid_get(w->session), w->target, TRUE)))
		return 0;

	/* line->str + line->attr == ascii str with formats */
	str  = fstring_reverse(line);

	fprintf(ll->file, "%ld %s\n", time(NULL), str);
	fflush(ll->file);

	g_free(str);

	return 0;
}

static void logs_window_new(window_t *w) {

	if (!w->target || !w->session || w->id == WINDOW_CONTACTS_ID || w->id == WINDOW_LASTLOG_ID)
		return;

	logs_log_new(session_uid_get(w->session), w->target, FALSE);
	logs_log_new(session_uid_get(w->session), w->target, TRUE);
}

static QUERY(logs_handler_newwin) {
	window_t *w = *(va_arg(ap, window_t **));

	logs_window_new(w);

	logs_buffer_raw_display(w);

	return 0;
}

static QUERY(logs_postinit) {
	window_t *w;
	for (w = windows; w; w = w->next)
		logs_window_new(w);
	return 0;
}

static QUERY(logs_handler_killwin)  {
	window_t *w = *(va_arg(ap, window_t **));

	// logs_log_new() is wrapper for logs_log_find()
	g_ptr_array_remove(logs_logs, logs_log_new(session_uid_get(w->session), w->target, FALSE));
	g_ptr_array_remove(logs_logs, logs_log_new(session_uid_get(w->session), w->target, TRUE));
	return 0;
}

static QUERY(logs_setvar_default) {
	xfree(config_logs_path);
	xfree(config_logs_timestamp);
	config_logs_path = xstrdup("~/.ekg2/logs/%S/%u");
	config_logs_timestamp = NULL;
	return 0;
}

static COMMAND(debug_logs) {
	int i;

	g_return_val_if_fail(logs_logs != NULL, 1);

	printq("generic_bold", (" fd session    uid        fname"));

	for (i = 0; i < logs_logs->len; i++) {
		logs_log_t *ll = g_ptr_array_index(logs_logs, i);
		session_t *s = session_find(ll->session);
		char *line = g_strdup_printf("%3s %-10s %-10s %s",
				ll->file ? ekg_itoa(fileno(ll->file)) : "-",
				(s && s->alias) ? s->alias  : ll->session,
				ll->uid,
				ll->fname);
		printq("generic", line);
		g_free(line);
	}
	return 0;
}

EXPORT int logs_plugin_init(int prio) {

	PLUGIN_CHECK_VER("logs");

	plugin_register(&logs_plugin, prio);

	query_connect(&logs_plugin, "set-vars-default", logs_setvar_default, NULL);
	query_connect(&logs_plugin, "protocol-message-post", logs_handler, NULL);
	query_connect(&logs_plugin, "irc-protocol-message", logs_handler_irc, NULL);
	query_connect(&logs_plugin, "ui-window-new",	logs_handler_newwin, NULL);
	query_connect(&logs_plugin, "ui-window-print",	logs_handler_raw, NULL);
	query_connect(&logs_plugin, "ui-window-kill",	logs_handler_killwin, NULL);
	query_connect(&logs_plugin, "protocol-status", logs_status_handler, NULL);
	query_connect(&logs_plugin, "config-postinit", logs_postinit, NULL);
	query_connect(&logs_plugin, "day-changed", logs_day_changed, NULL);
	query_connect(&logs_plugin, "session-variable-changed", logs_session_var_changed, NULL);
	/* XXX, implement UI_WINDOW_TARGET_CHANGED, IMPORTANT!!!!!! */

	variable_add(&logs_plugin, ("encoding"), VAR_STR, 1, &config_logs_encoding, NULL, NULL, NULL);
	variable_add(&logs_plugin, ("max_open_files"), VAR_INT, 1, &config_logs_max_files, &logs_variable_changed, NULL, NULL);
	variable_add(&logs_plugin, ("log"), VAR_MAP, 1, &config_logs_log, &logs_variable_changed,
			variable_map(3,
				LOG_FORMAT_NONE, 0, "none",
				LOG_FORMAT_SIMPLE, LOG_FORMAT_XML, "simple",
				LOG_FORMAT_XML, LOG_FORMAT_SIMPLE, "xml"),
			NULL);
	variable_add(&logs_plugin, ("log_raw"), VAR_BOOL, 1, &config_logs_log_raw, &logs_variable_changed, NULL, NULL);
	variable_add(&logs_plugin, ("log_ignored"), VAR_INT, 1, &config_logs_log_ignored, NULL, NULL, NULL);
	variable_add(&logs_plugin, ("log_status"), VAR_BOOL, 1, &config_logs_log_status, &logs_variable_changed, NULL, NULL);
	variable_add(&logs_plugin, ("path"), VAR_DIR, 1, &config_logs_path, &logs_variable_changed, NULL, NULL);
	variable_add(&logs_plugin, ("remind_number"), VAR_INT, 1, &config_logs_remind_number, NULL, NULL, NULL);
	variable_add(&logs_plugin, ("timestamp"), VAR_STR, 1, &config_logs_timestamp, NULL, NULL, NULL);

	command_add(&logs_plugin, ("_logs"), NULL, debug_logs, 0, NULL);

	logs_logs = g_ptr_array_new_with_free_func(logs_log_destroy);

	return 0;
}

static int logs_plugin_destroy() {

	g_ptr_array_free(logs_logs, TRUE);

	plugin_unregister(&logs_plugin);
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
