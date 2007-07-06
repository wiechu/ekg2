/*
 *  (C) Copyright 2007 EKG2 authors
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

#include "stuff.h" /* config_version here */
#include "themes.h" /* print() & _() */
#include "xmalloc.h" /* x*() */

/**
 * config_upgrade()
 *
 * Check current configuration file version and upgrade it if needed. Print additional info about changes.
 */

void config_upgrade() {
	const int current_config_version = 3;

	if (xstrcasecmp(console_charset, config_console_charset)) 
		print("console_charset_bad", console_charset, config_console_charset);
	else if (config_version == 0)
		print("console_charset_using", config_console_charset);

	if (config_version >= current_config_version)
		return;
	else
		print("config_upgrade_begin");
	
	switch (config_version) { /* versions MUST be sorted, break MUST NOT be used */
		case 0: /* jabber SASL behavior change */
			print("config_upgrade_major", 
				_("We've started using XMPP SASL AUTH by default, so if you're unable to connect to your favorite jabber server,"	\
				"please send us debug info and try to set (within appropriate session):\n"
				"/session disable_sasl 2"), "1");

		case 1: /* display_ack values change */
			print("config_upgrade_minor", 
				_("Variable display_ack's values have been changed. "	\
				"An update is done to your settings, but please check the new values."), "2");

			switch (config_display_ack) {
				case 1: config_display_ack = 31; break;
				case 2: config_display_ack = 1; break;
				case 3: config_display_ack = 2; break;
			}

		case 2: /* allow_autoresponder session var */
			print("config_upgrade_minor", 
				_("'allow_autoresponder' session variables have been replaced by 'allowed_sessions' plugin variable. "	\
				"The same way future plugins will be enabled."), "3");

		case 3:
			print("config_upgrade_minor",
				_("'logs:away_log' plugin variable have been replaced by 'away_log' irc session variable. " \
				"Also away_log_* formats have been changed to irc_awaylog_* formats. Enjoy"), "4");
	}

	config_version = current_config_version;
	if (config_save_quit != 2)
		print("config_upgrade_end");
}

