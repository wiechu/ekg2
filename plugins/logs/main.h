/* $Id$ */

/*
 *  (C) Copyright 2003-2004 Leszek Krupiński <leafnode@wafel.com>
 *		       2005 Adam Mikuta <adamm@ekg2.org>
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

#ifndef __logs_h__
#define __logs_h__

#include <stdio.h>

typedef struct {
	char *session;	/* session name */
	char *uid;	/* uid of user */
	char *fname;
	FILE *file;
	int format;
	int daychanged : 1;
} logs_log_t;

/* log ff types... */
typedef enum {
	LOG_FORMAT_NONE = 0,
	LOG_FORMAT_SIMPLE,
	LOG_FORMAT_XML,
	LOG_FORMAT_IRSSI,
	LOG_FORMAT_RAW,
} log_format_t;


static int logs_open_file(logs_log_t *ll);

static void logs_open_files_check();

static void logs_irssi_sysmsg(logs_log_t *log, const char *text);


#endif
