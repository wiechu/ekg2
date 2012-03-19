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

#ifndef __EKG_CONNECTION_H
#define __EKG_CONNECTION_H
#ifndef EKG2_WIN32_NOFUNCTION

#include "plugins.h"
#include "sessions.h"
#include "srv.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef INADDR_NONE
#  define INADDR_NONE (unsigned long) 0xffffffff
#endif


typedef struct connection_data_t connection_data_t;

typedef void (*ekg2_connect_handler_t) (connection_data_t *cd);
typedef void (*ekg2_connect_failure_t) (connection_data_t *cd);
typedef void (*ekg2_connection_input_callback_t) (connection_data_t *cd, GString *buffer);
typedef void (*ekg2_connection_failure_t) (connection_data_t *cd);
typedef void (*ekg2_connection_disconnect_t) (session_t *s, const char *reason, int type);

connection_data_t *ekg2_connection_new(session_t *session, guint16 defport);

void ekg2_connection_set_servers(connection_data_t *cd, const gchar *servers);
void ekg2_connection_set_srv(connection_data_t *cd, gchar *service, gchar *domain);


GError *ekg2_connection_get_error(connection_data_t *cd);
session_t *ekg2_connection_get_session(connection_data_t *cd);

void
ekg2_connect_full(connection_data_t *cd,
		ekg2_connect_handler_t connect_handler,
		ekg2_connect_failure_t connect_failure_handler,
		ekg2_connection_input_callback_t input_callback,
		ekg2_connection_failure_t failure_callback);

void
ekg2_connect(connection_data_t *cd,
		ekg2_connect_handler_t connect_handler,
		ekg2_connection_input_callback_t input_callback,
		ekg2_connection_disconnect_t disconnect_handler);


int ekg2_connection_write(connection_data_t *cd, gconstpointer buffer, gsize length);

void ekg2_connection_close(connection_data_t **acd);
#ifdef __cplusplus
}
#endif

#endif /* EKG2_WIN32_NOFUNCTION */
#endif /* __EKG_CONNECTION_H */

/*
 * Local Variables:
 * mode: c
 * c-file-style: "k&r"
 * c-basic-offset: 8
 * indent-tabs-mode: t
 * End:
 */
