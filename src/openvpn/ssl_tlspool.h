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
 * @file Control Channel TLS Pool Backend
 */

#ifndef SSL_TLSPOOL_H_
#define SSL_TLSPOOL_H_

#include "syshead.h"

#include <tlspool/commands.h>

#if defined(ENABLE_PKCS11)
#warning "You should not need PKCS #11 when TLS credentials are managed by the TLS Pool"
#endif


/**
 * Structure that wraps the TLS context. Contents differ depending on the
 * SSL library used.
 *
 * Either \c priv_key_pkcs11 or \c priv_key must be filled in.
 */
struct tls_root_ctx {
	bool initialised;	/**< True if the context has been initialised */

	int poolfd;		/**< The file descriptor for the TLS Pool */
	starttls_t tlsdata_prototype;  /**< Prototype starttls_XXX() settings */
};

struct key_state_ssl {
	int plaintext;		/**< FD for the  plaintext side of TLS Pool */
	int ciphertext;		/**< FD for the ciphertext side of TLS Pool */
	struct tlspool_command cmd;	/**< TLS Pool command buffer */
};


#endif /* SSL_TLSPOOL_H_ */
