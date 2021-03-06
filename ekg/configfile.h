/* $Id$ */

/*
 *  (C) Copyright 2001-2003 Wojtek Kaniewski <wojtekka@irc.pl>
 *			    Robert J. Wo�ny <speedy@ziew.org>
 *			    Pawe� Maziarz <drg@go2.pl>
 *			    Dawid Jarosz <dawjar@poczta.onet.pl>
 *			    Piotr Domagalski <szalik@szalik.net>
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

#ifndef __EKG_CONFIGFILE_H
#define __EKG_CONFIGFILE_H

#ifndef EKG2_WIN32_NOFUNCTION

#include "plugins.h"

#ifdef __cplusplus
extern "C" {
#endif

void config_postread();
gboolean ekg_fprintf(GOutputStream *f, const gchar *format, ...)
	G_GNUC_PRINTF(2, 3);
GObject *config_open(const gchar *path_format, const gchar *mode, ...)
	G_GNUC_PRINTF(1, 3);
gboolean config_commit(void);

int config_read(const gchar *plugin_name);
int config_read_plugins();
void config_write();
int config_write_partly(plugin_t *plugin, const char **vars);
void debug_write_crash();

#ifdef __cplusplus
}
#endif

#endif

#endif /* __EKG_CONFIGFILE_H */

/*
 * Local Variables:
 * mode: c
 * c-file-style: "k&r"
 * c-basic-offset: 8
 * indent-tabs-mode: t
 * End:
 */
