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

#include "jabber.h"

#include <string.h>

/**
 * base16_encode()
 *
 * Return base16 hash of @a data
 *
 * @return <b>static</b> with 32 digit BASE16 HASH + NUL char.
 */

static const char *base16_encode(const unsigned char *data) {
	static char result[33];
	int i;

	if (!data) return NULL;

	for (i = 0; i < 16; i++)
		snprintf(&result[i * 2], 3, "%02hhx", data[i]);

	result[32] = 0;
	return result;
}

/**
 * challenge_digest()
 *
 * Return base16 encoded hash for SASL MD5 CHALLENGE
 *
 * @return <b>static</b> buffer with 32 digit BASE16 HASH + NUL char
 */
static const char *challenge_digest(const char *sid, const char *password, const char *nonce, const char *cnonce, const char *xmpp_temp, const char *realm) {
	unsigned char digest[20];

	const char *convnode, *convpasswd;	/* sid && password encoded in UTF-8 */
	char *ha1, *ha2;
	char *kd;
	gsize size = 16;
	GChecksum *chksum;

/* ZERO STEP -> recode */
	convnode = ekg_locale_to_utf8_use(sid);
	convpasswd = ekg_locale_to_utf8_use(password);

/* FIRST STEP */
	kd = g_strdup_printf("%s:%s:%s", convnode, realm, convpasswd);

	recode_xfree(sid, convnode);
	recode_xfree(password, convpasswd);

	chksum = g_checksum_new(G_CHECKSUM_MD5);
	g_checksum_update(chksum, (const guchar *)kd, xstrlen(kd));
	g_checksum_get_digest(chksum, digest, &size);
	g_checksum_free(chksum);

	xfree(kd);

/* SECOND STEP */
	kd = g_strdup_printf("xxxxxxxxxxxxxxxx:%s:%s", nonce, cnonce);
	memcpy(kd, digest, size);

	chksum = g_checksum_new(G_CHECKSUM_MD5);
	g_checksum_update(chksum, (const guchar *)kd, size + 1 + xstrlen(nonce) + 1 + xstrlen(cnonce));
	g_checksum_get_digest(chksum, digest, &size);
	g_checksum_free(chksum);

	xfree(kd);

/* 3a) DATA */
	ha1 = g_strdup(base16_encode(digest));

	chksum = g_checksum_new(G_CHECKSUM_MD5);
	g_checksum_update(chksum, (const guchar *)xmpp_temp, xstrlen(xmpp_temp));
	g_checksum_get_digest(chksum, digest, &size);
	g_checksum_free(chksum);
/* 3b) DATA */
	ha2 = g_strdup(base16_encode(digest));

/* THIRD STEP */
	kd = g_strdup_printf("%s:%s:00000001:%s:auth:%s", ha1, nonce, cnonce, ha2);

	g_free(ha1);
	g_free(ha2);

	chksum = g_checksum_new(G_CHECKSUM_MD5);
	g_checksum_update(chksum, (const guchar *)kd, xstrlen(kd));
	g_checksum_get_digest(chksum, digest, &size);
	g_checksum_free(chksum);

	g_free(kd);

/* FINAL */
	return base16_encode(digest);
}

static char *sasl_auth_digest_md5(session_t *s, const char *username, const char *password, const char *nonce, const char *realm) {
	jabber_private_t *j =  s->priv;
	char tmp_cnonce[32];
	const char *auth_resp;
	char *encoded, *cnonce, *temp;;
	int i;

	if (!realm) realm = j->server;

	/* generate random number using high-order bytes man 3 rand() */
	for (i=0; i < sizeof(tmp_cnonce); i++)
		tmp_cnonce[i] = (char) (256.0*rand()/(RAND_MAX+1.0));

	cnonce = base64_encode(tmp_cnonce, sizeof(tmp_cnonce));

	temp = g_strdup_printf(":xmpp/%s", realm);
	auth_resp = challenge_digest(username, password, nonce, cnonce, temp, realm);
	g_free(temp);

	session_set(s, "__sasl_excepted", auth_resp);

	temp = g_strdup_printf("AUTHENTICATE:xmpp/%s", realm);
	auth_resp = challenge_digest(username, password, nonce, cnonce, temp, realm);
	g_free(temp);

	temp = g_strdup_printf(
			"username=\"%s\",realm=\"%s\",nonce=\"%s\",cnonce=\"%s\",nc=00000001,"
			"digest-uri=\"xmpp/%s\",qop=auth,response=%s,charset=utf-8",
			username, realm, nonce, cnonce, realm, auth_resp);

	g_free(cnonce);

	encoded = base64_encode(temp, xstrlen(temp));	/* XXX base64_encoded() CHANGED!! str->len+1 ? */

	g_free(temp);

	return encoded;
}

char *jabber_sasl_digest_md5_response(session_t *s, char *challenge, const char *username, const char *password) {
	jabber_private_t *j =  s->priv;
	char **arr;
	char *retval, *nonce = NULL, *realm = NULL;
// XXX	char *rspauth	= NULL;
	int i;

	/* maybe we need to change/create another one parser... i'm not sure. please notify me, I'm lazy, sorry */
	/* for chrome.pl and jabber.autocom.pl it works */

	arr = array_make(challenge, "=,", 0, 1, 1);

	/* check data */
	if (g_strv_length(arr) & 1) {
		debug_error("Parsing var<=>value failed, NULL....\n");
		jabber_handle_disconnect(s, "IE, Current SASL support for ekg2 cannot handle with this data, sorry.", EKG_DISCONNECT_FAILURE);
		g_strfreev(arr);
		j->parser = NULL;
		return NULL;
	}

	/* parse data */
	i = 0;
	while (arr[i]) {
		char *tmp = strip_spaces(arr[i]);
		debug("md5_digest [%d] %s: %s\n", i / 2, arr[i], __(arr[i+1]));
		if (!xstrcmp(tmp, "realm"))		realm	= arr[i+1];
// XXX		else if (!xstrcmp(tmp, "rspauth"))	rspauth	= arr[i+1];
		else if (!xstrcmp(tmp, "nonce"))	nonce	= arr[i+1];
		i++;
		if (arr[i]) i++;
	}

	retval = sasl_auth_digest_md5(s, username, password, nonce, realm);

	g_strfreev(arr);

	return retval;
}

char *jabber_sasl_cram_md5_response(session_t *s, char *challenge, const char *username, const char *password) {
	char *digstr, *tmp, *retval;
	gsize i, len, block_size = 64;
	GChecksum *idigest = g_checksum_new(G_CHECKSUM_MD5);
	GChecksum *odigest = g_checksum_new(G_CHECKSUM_MD5);
	guchar *buf = g_malloc0(block_size);
	guchar *pad = g_malloc0(block_size);

	if (xstrlen(password) > block_size) {
		gsize len = block_size;
		g_checksum_update(idigest, (const guchar *)password, xstrlen(password));
		g_checksum_get_digest(idigest, buf, &len);
		g_checksum_reset(idigest);
	} else
		memcpy(buf, password, xstrlen(password));

	/* ipad */
	for (i = 0; i < block_size; i++)
		pad[i] = 0x36 ^ buf[i];
	g_checksum_update(idigest, pad, block_size);

	/* opad */
	for (i = 0; i < block_size; i++)
		pad[i] = 0x5c ^ buf[i];
	g_checksum_update(odigest, pad, block_size);

	g_checksum_update(idigest, (const guchar *)challenge, xstrlen(challenge));

	g_checksum_get_digest(idigest, buf, &len);
	g_checksum_update(odigest, buf, len);
	g_checksum_get_digest(odigest, buf, &len);

	digstr = g_strdup(g_checksum_get_string(odigest));

	g_checksum_free(idigest);
	g_checksum_free(odigest);
	g_free(buf);
	g_free(pad);

	tmp = g_strdup_printf("%s %s", username, digstr);
	retval = base64_encode(tmp, xstrlen(tmp));
	g_free(tmp);
	g_free(digstr);
	return retval;
}

/**
 * tlen_auth_digest()
 *
 * @note	Tlen Authentication was stolen from libtlen calc_passcode() with magic stuff (C) libtlen's developer and Piotr Pawłow<br>
 *		see: http://libtlen.sourceforge.net/
 *
 * Return SHA1 hash for tlen auth<br>
 *
 * @return <b>static</b> buffer, with 40 digit SHA1 hash + NUL char
 */

char *tlen_auth_digest(const char *sid, const char *password) {
	GChecksum *ctx;
	char *epasswd;
	unsigned char digest[20];
	static char result[41];
	gsize len = 20;
	int i;

	/* stolen from libtlen function calc_passcode() Copyrighted by libtlen's developer and Piotr Pawłow */
	int	magic1 = 0x50305735, magic2 = 0x12345671, sum = 7;
	char	z;
	while ((z = *password++) != 0) {
		if (z == ' ' || z == '\t') continue;
		magic1 ^= (((magic1 & 0x3f) + sum) * z) + (magic1 << 8);
		magic2 += (magic2 << 8) ^ magic1;
		sum += z;
	}
	magic1 &= 0x7fffffff;
	magic2 &= 0x7fffffff;

	epasswd = saprintf("%08x%08x", magic1, magic2);

	ctx = g_checksum_new(G_CHECKSUM_SHA1);

	g_checksum_update(ctx, (const guchar *)sid, xstrlen(sid));
	g_checksum_update(ctx, (const guchar *)epasswd, xstrlen(epasswd));

	g_checksum_get_digest(ctx, digest, &len);

	g_free(epasswd);

	for (i = 0; i < 20; i++)
		sprintf(result + i * 2, "%.2x", digest[i]);

	return result;
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
