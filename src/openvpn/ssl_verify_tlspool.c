/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2010 OpenVPN Technologies, Inc. <sales@openvpn.net>
 *  Copyright (C) 2010 Fox Crypto B.V. <openvpn@fox-it.com>
 *  Copyright (C) 2015 ARPA2.net <rick@openfortress.nl>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program (see the file COPYING included with this
 *  distribution); if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/**
 * @file Control Channel Verification Module PolarSSL backend
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#if defined(ENABLE_CRYPTO) && defined(ENABLE_BACKEND_TLSPOOL)

/**
 * NOTE WELL:
 *
 * The TLS Pool backend redirects all TLS responsibilities to the TLS Pool.
 * This includes verification of X.509 certificate structures.  As a result,
 * little of no information can be derived from the TLS session, let alone
 * verifications be independently mounted.
 *
 * For reasons of not wanting to disturb the coded logic of OpenVPN, the
 * routines below return trivial truth values when requested to perform
 * verifications.  The assumption made here is that a TLS connection never
 * comes back from the TLS Pool unless the handshake was sufficiently
 * authenticated.
 *
 * The place to tighten X.509 certificate handling for OpenVPN moves from
 * this individual application to the TLS Pool, making it subject to central
 * co-ordination or provisioning.
 */

#include "ssl_verify.h"

#define MAX_SUBJECT_LENGTH 256

result_t backend_x509_get_username (char *cn, int cn_len, char *x509_username_field, openvpn_x509_cert_t *cert) {
	//TODO// Return remoteid
	strncpy (cn, "user@remote.dom", cn_len);
	return SUCCESS;
}

char * backend_x509_get_serial (openvpn_x509_cert_t *cert, struct gc_arena *gc) {
	return NULL;
}

char * backend_x509_get_serial_hex (openvpn_x509_cert_t *cert, struct gc_arena *gc) {
	return NULL;
}


unsigned char *x509_get_sha1_hash (openvpn_x509_cert_t *cert, struct gc_arena *gc) {
	return NULL;
}

char *x509_get_subject(openvpn_x509_cert_t *cert, struct gc_arena *gc) {
	//TODO// Return remoteid
	return "user@remote.dom";
}

/*
 * Save X509 fields to environment, using the naming convention:
 *
 * X509_{cert_depth}_{name}={value}
 */
void x509_setenv (struct env_set *es, int cert_depth, openvpn_x509_cert_t *cert)
{
	;
}

result_t x509_verify_ns_cert_type(const openvpn_x509_cert_t *cert, const int usage) {
	return SUCCESS;
}

result_t x509_verify_cert_ku (openvpn_x509_cert_t *cert, const unsigned * const expected_ku, int expected_len) {
	return SUCCESS;
}

result_t x509_verify_cert_eku (openvpn_x509_cert_t *cert, const char * const expected_oid) {
	return SUCCESS;
}

result_t x509_write_pem(FILE *peercert_file, openvpn_x509_cert_t *peercert) {
	return FAILURE;
}

/*
 * check peer cert against CRL
 */
result_t x509_verify_crl(const char *crl_file, openvpn_x509_cert_t *cert, const char *subject) {
	return SUCCESS;
}

#ifdef ENABLE_X509_TRACK

void x509_track_add (const struct x509_track **ll_head, const char *name, int msglevel, struct gc_arena *gc) {
	;
}

/* worker method for setenv_x509_track */
static void do_setenv_x509 (struct env_set *es, const char *name, char *value, int depth) {
	;
}

void x509_setenv_track (const struct x509_track *xt, struct env_set *es, const int depth, X509 *x509) {
	return;
}

#endif /* ENABLE_X509_TRACK */

#endif /* defined(ENABLE_CRYPTO) && defined(ENABLE_BACKEND_TLSPOOL) */
