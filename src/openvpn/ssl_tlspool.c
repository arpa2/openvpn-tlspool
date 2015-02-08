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

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#if defined(ENABLE_CRYPTO) && defined(ENABLE_BACKEND_TLSPOOL)

#include "errlevel.h"
#include "ssl_backend.h"
#include "base64.h"
#include "buffer.h"
#include "misc.h"
#include "manage.h"
#include "ssl_common.h"

#include <tlspool/commands.h>

/**
 *  prototype for struct tls_session from ssl_common.h
 */
struct tls_session;


static int poolfd = -1;		/**< UNIX domain socket for the TLS Pool */
static int poolerrno = 0;	/**< Sticky form of TLS Pool error number */


/*
 *
 * Functions used in ssl.c which must be implemented by the backend SSL library
 *
 */

/**
 * Perform any static initialisation necessary by the TLS Pool.
 * Called on OpenVPN initialisation
 */
void tls_init_lib () {
	char *path = "/var/run/tlspool.sock";
	poolerrno = 0;
	struct sockaddr_un sun;
	//TODO// Permit a setting for TLS Pool socket path
	if (strlen (path) + 1 > sizeof (sun.sun_path)) {
		poolerrno = ENAMETOOLONG;
	} else {
		CLEAR (sun);
		strcpy (sun.sun_path, path);
		sun.sun_family = AF_UNIX;
		poolfd = socket (AF_UNIX, SOCK_STREAM, 0);
		if (poolfd != -1) {
			if (connect (poolfd, (struct sockaddr *) &sun, SUN_LEN (&sun)) == -1) {
				close (poolfd);
				poolfd = -1;
			}
		}
	}
	if (poolfd == -1) {
		msg (M_FATAL, "Failed to connect to the TLS Pool");
		openvpn_exit (OPENVPN_EXIT_STATUS_ERROR);
	}
}

/**
 * Free any global TLS Pool-specific data structures.
 */
void tls_free_lib () {
	if (poolfd != -1) {
		close (poolfd);
		poolfd = -1;
	}
}


/**
 * Clear the TLS Pool error state.
 */
void tls_clear_error () {
	poolerrno = 0;
}


/**
 * Return the maximum TLS version (as a TLS_VER_x constant)
 * supported by the TLS Pool implementation.  This may need an API
 * version number match when TLS 1.3 or TLS 2.0 is introduced.
 *
 * @return 		One of the TLS_VER_x constants (but not TLS_VER_BAD).
 */
int tls_version_max (void) {
	return TLS_VER_1_2;
}

/**
 * Initialise a TLS Pool-specific TLS context for a server.
 *
 * @param ctx		TLS context to initialise
 */
void tls_ctx_server_new (struct tls_root_ctx *ctx) {
	ASSERT (NULL != ctx);
	ASSERT (poolfd != -1);
	CLEAR (*ctx);
	ctx->initialised = true;
}

/**
 * Initialises a TLS Pool-specific TLS context for a client.
 *
 * @param ctx		TLS context to initialise
 */
void tls_ctx_client_new (struct tls_root_ctx *ctx) {
	ASSERT (NULL != ctx);
	ASSERT (poolfd != -1);
	CLEAR (*ctx);
	ctx->tlsdata_prototype.ipproto = IPPROTO_TCP;
	ctx->initialised = true;
}

/**
 * The internal starttls function initiates a context with sockets for both
 * the plaintext and ciphertext side of the connection.  Inasfar as they are
 * set, local_id and remote_id variables will be used to identify end points.
 *
 * @param ctx		TLS context to initialise
 * @param is_server	Initialise as a server?
 */
static bool starttls (struct key_state_ssl *ks_ssl,
		const struct tls_root_ctx *ssl_ctx,
		bool is_server) {
	int plainsox [2];
	bool processing;
	char anc [CMSG_SPACE (sizeof (int))];
	struct iovec iov;
	struct cmsghdr *cmsg;
	struct tlspool_command *cmd;
	struct msghdr mh;

	cmd = &ks_ssl->cmd;
	//
	// Obtain a socket pair for the plaintext side of the TLS Pool
	if (socketpair (SOCK_STREAM, AF_UNIX, 0, plainsox) < 0) {
		ks_ssl->plaintext = ks_ssl->ciphertext = -1;
		return false;
	}
	//
	// Attach plainsox [0] to the TLS Pool on the plaintext side
	cmd->pio_reqid = 666;	/* Static: No asynchronous behaviour */
	cmd->pio_cbid = 0;
	cmd->pio_cmd = is_server? PIOC_STARTTLS_SERVER_V1: PIOC_STARTTLS_CLIENT_V1;
	memcpy (&cmd->pio_data.pioc_starttls, &ssl_ctx->tlsdata_prototype, sizeof (struct pioc_starttls));
	CLEAR (iov);
	iov.iov_base = &cmd;
	iov.iov_len = sizeof (cmd);
	CLEAR (mh);
	mh.msg_iov = &iov;
	mh.msg_iovlen = 1;
	mh.msg_control = anc;
	mh.msg_controllen = sizeof (anc);
	CLEAR (cmsg);
	cmsg = CMSG_FIRSTHDR (&mh);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type =SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN (sizeof (int));
	* (int *) CMSG_DATA (cmsg) = plainsox [0];
	if (sendmsg (poolfd, &mh, 0) == -1) {
		close (plainsox [0]);
		close (plainsox [1]);
		ks_ssl->plaintext = ks_ssl->ciphertext = -1;
		return false;
	}
	//
	// Now handle any interaction desired by the TLS Pool
	processing = true;
	while (processing) {
		bool failure = false;
		mh.msg_control = anc;
		mh.msg_controllen = sizeof (anc);
		if (recvmsg (poolfd, &mh, 0) == -1) {
			failure = true;
		} else {
			switch (cmd->pio_cmd) {
			case PIOC_ERROR_V1:
				errno = poolerrno = cmd->pio_data.pioc_error.tlserrno;
				msg (D_TLS_ERRORS, "%s: %s", strerror (cmd->pio_data.pioc_error.tlserrno), cmd->pio_data.pioc_error.message);
				failure = true;
				break;
			case PIOC_STARTTLS_LOCALID_V1:
				// Simple strcmp() since no virtual hosting yet
				if ((*ssl_ctx->tlsdata_prototype.localid) && (strcmp (ssl_ctx->tlsdata_prototype.localid, cmd->pio_data.pioc_starttls.localid) != 0)) {
					// Reject the proposed localid
					*cmd->pio_data.pioc_starttls.localid = '\0';
				}
				mh.msg_control = NULL;
				mh.msg_controllen = 0;
				if (sendmsg (poolfd, &mh, 0) == -1) {
					poolfd = EIO;
					failure = true;
				}
				break;
			case PIOC_STARTTLS_CLIENT_V1:
			case PIOC_STARTTLS_SERVER_V1:
				// Success!
				processing = 0;
				break;
			default:
				// V1 protocol error
				poolerrno = EPROTO;
				msg (D_TLS_ERRORS, "Unexpected response while talking to the TLS Pool");
				failure = true;
				break;
			}
		}
		if (failure) {
			close (plainsox [0]);
			close (plainsox [1]);
			ks_ssl->plaintext = ks_ssl->ciphertext = -1;
			return false;
		}
	}
	//
	// Collect file descriptors into the tls_root_ctx
	close (plainsox [0]);	// It is now duplicated by the TLS Pool
	ks_ssl->plaintext = plainsox [1];
	ks_ssl->ciphertext = * (int *) CMSG_DATA (cmsg);
	return true;
}

/**
 * Frees the TLS Pool-specific TLSv1 context
 *
 * @param ctx		TLS context to free
 */
void tls_ctx_free (struct tls_root_ctx *ctx) {
	ASSERT (NULL != ctx);
	if (ctx->initialised) {
		ctx->initialised = false;
	}
	CLEAR (*ctx);
}

/**
 * Checks whether the given TLS context is initialised
 *
 * @param ctx		TLS context to check
 *
 * @return	true if the context is initialised, false if not.
 */
bool tls_ctx_initialised (struct tls_root_ctx *ctx) {
	ASSERT (NULL != ctx);
	return ctx->initialised;
}

/**
 * Set any TLS Pool specific options.
 *
 * Examples include disabling session caching, the password callback to use,
 * and session verification parameters.
 *
 * @param ctx		TLS context to set options on
 * @param ssl_flags	SSL flags to set
 */
void tls_ctx_set_options (struct tls_root_ctx *ctx, unsigned int ssl_flags) {
	msg (D_TLS_ERRORS, "Attempt to set unsupported set on TLS Pool");
}

/**
 * Set the local identity to be used by the TLS Pool.
 *
 * @param ctx		TLS context to setup with the local identity
 * @param localid	NUL-terminated string for the local identity
 */
void tls_ctx_set_localid (struct tls_root_ctx *ctx, char *localid) {
	if (strlen (localid) + 1 > sizeof (ctx->tlsdata_prototype.localid)) {
		msg (D_TLS_ERRORS, "Cut-off on too long local identity string");
	}
	strncpy (ctx->tlsdata_prototype.localid, localid, sizeof (ctx->tlsdata_prototype.localid));
}

/**
 * Set the remote identity to be assured by the TLS Pool.
 *
 * @param ctx		TLS context to setup with the remote identity
 * @param remoteid	NUL-terminated string for the remote identity
 */
void tls_ctx_set_remoteid (struct tls_root_ctx *ctx, char *remoteid) {
	if (strlen (remoteid) + 1 > sizeof (ctx->tlsdata_prototype.remoteid)) {
		msg (D_TLS_ERRORS, "Cut-off on too long remote identity string");
	}
	strncpy (ctx->tlsdata_prototype.remoteid, remoteid, sizeof (ctx->tlsdata_prototype.remoteid));
}

/**
 * Restrict the list of ciphers that can be used within the TLS context.
 *
 * @param ctx		TLS context to restrict, must be valid.
 * @param ciphers	String containing : delimited cipher names, or NULL to use
 *					sane defaults.
 */
void tls_ctx_restrict_ciphers (struct tls_root_ctx *ctx, const char *ciphers) {
	ASSERT (NULL != ctx);
	msg (D_TLS_ERRORS, "Cannot restrict cipher suites -- TLS is delegated to the TLS Pool");
}

/**
 * Load Diffie Hellman Parameters, and load them into the TLS Pool context.
 *
 * @param ctx			TLS context to use
 * @param dh_file		The file name to load the parameters from, or
 * 				"[[INLINE]]" in the case of inline files.
 * @param dh_file_inline	A string containing the parameters
 */
void tls_ctx_load_dh_params (struct tls_root_ctx *ctx, const char *dh_file,
    const char *dh_file_inline) {
	msg (D_TLS_ERRORS, "Cannot set DH params -- TLS is delegated to the TLS Pool");
}

/**
 * Load Elliptic Curve Parameters, and load them into the TLS Pool context.
 *
 * @param ctx          TLS context to use
 * @param curve_name   The name of the elliptic curve to load.
 */
void tls_ctx_load_ecdh_params (struct tls_root_ctx *ctx, const char *curve_name
    ) {
	msg (D_TLS_ERRORS, "Cannot set ECDH params -- TLS is delegated to the TLS Pool");
}

/**
 * Load PKCS #12 file for key, cert and (optionally) CA certs, and add to
 * library-specific TLS context.
 *
 * @param ctx			TLS context to use
 * @param pkcs12_file		The file name to load the information from, or
 * 				"[[INLINE]]" in the case of inline files.
 * @param pkcs12_file_inline	A string containing the information
 *
 * @return 			1 if an error occurred, 0 if parsing was
 * 				successful.
 */
int tls_ctx_load_pkcs12 (struct tls_root_ctx *ctx, const char *pkcs12_file,
    const char *pkcs12_file_inline, bool load_ca_file
    ) {
	msg (D_TLS_ERRORS, "Cannot load PKCS #12 -- TLS is delegated to the TLS Pool");
}

/**
 * Use Windows cryptoapi for key and cert, and add to library-specific TLS
 * context.
 *
 * @param ctx			TLS context to use
 * @param crypto_api_cert	String representing the certificate to load.
 */
#ifdef ENABLE_CRYPTOAPI
void tls_ctx_load_cryptoapi (struct tls_root_ctx *ctx, const char *cryptoapi_cert) {
	msg (D_TLS_ERRORS, "Cannot load CryptoAPI -- TLS is delegated to the TLS Pool");
}
#endif /* WIN32 */

/**
 * Load certificate file into the given TLS context. If the given certificate
 * file contains a certificate chain, load the whole chain.
 *
 * @param ctx			TLS context to use
 * @param cert_file		The file name to load the certificate from, or
 * 				"[[INLINE]]" in the case of inline files.
 * @param cert_file_inline	A string containing the certificate
 */
void tls_ctx_load_cert_file (struct tls_root_ctx *ctx, const char *cert_file,
    const char *cert_file_inline) {
	msg (D_TLS_ERRORS, "Cannot load certificate -- TLS is delegated to the TLS Pool");
}

/**
 * Load private key file into the given TLS context.
 *
 * @param ctx			TLS context to use
 * @param priv_key_file		The file name to load the private key from, or
 * 				"[[INLINE]]" in the case of inline files.
 * @param priv_key_file_inline	A string containing the private key
 *
 * @return 			1 if an error occurred, 0 if parsing was
 * 				successful.
 */
int tls_ctx_load_priv_file (struct tls_root_ctx *ctx, const char *priv_key_file,
    const char *priv_key_file_inline
    ) {
	msg (D_TLS_ERRORS, "Cannot load private key -- TLS is delegated to the TLS Pool");
}

#ifdef MANAGMENT_EXTERNAL_KEY

/**
 * Tell the management interface to load the given certificate and the external
 * private key matching the given certificate.
 *
 * @param ctx			TLS context to use
 * @param cert_file		The file name to load the certificate from, or
 * 				"[[INLINE]]" in the case of inline files.
 * @param cert_file_inline	A string containing the certificate
 *
 * @return 			1 if an error occurred, 0 if parsing was
 * 				successful.
 */
int tls_ctx_use_external_private_key (struct tls_root_ctx *ctx,
    const char *cert_file, const char *cert_file_inline) {
	msg (D_TLS_ERRORS, "Cannot use external private key -- TLS is delegated to the TLS Pool");
}
#endif


/**
 * Load certificate authority certificates from the given file or path.
 *
 * Note that not all SSL libraries support loading from a path.
 *
 * @param ctx			TLS context to use
 * @param ca_file		The file name to load the CAs from, or
 * 				"[[INLINE]]" in the case of inline files.
 * @param ca_file_inline	A string containing the CAs
 * @param ca_path		The path to load the CAs from
 */
void tls_ctx_load_ca (struct tls_root_ctx *ctx, const char *ca_file,
    const char *ca_file_inline, const char *ca_path, bool tls_server
    ) {
	msg (D_TLS_ERRORS, "Cannot load CA -- TLS is delegated to the TLS Pool");
}

/**
 * Load extra certificate authority certificates from the given file or path.
 * These Load extra certificates that are part of our own certificate
 * chain but shouldn't be included in the verify chain.
 *
 *
 * @param ctx				TLS context to use
 * @param extra_certs_file		The file name to load the certs from, or
 * 					"[[INLINE]]" in the case of inline files.
 * @param extra_certs_file_inline	A string containing the certs
 */
void tls_ctx_load_extra_certs (struct tls_root_ctx *ctx, const char *extra_certs_file,
    const char *extra_certs_file_inline
    ) {
	msg (D_TLS_ERRORS, "Cannot load extra certs -- TLS is delegated to the TLS Pool");
}

#ifdef ENABLE_CRYPTO_POLARSSL
/**
 * Add a personalisation string to the PolarSSL RNG, based on RFC 5075
 * random material.
 *
 * @param ctx			TLS context to use
 */
void tls_ctx_personalise_random(struct tls_root_ctx *ctx) {
	//TODO:RFC5075//
	msg (M_WARN, "Personalisation of randomness has not been implemented yet");
}
#endif

/* **************************************
 *
 * Key-state specific functions
 *
 ***************************************/

/**
 * Initialise the SSL channel part of the given key state. Settings will be
 * loaded from a previously initialised TLS context.
 *
 * @param ks_ssl	The SSL channel's state info to initialise
 * @param ssl_ctx	The TLS context to use when initialising the channel.
 * @param is_server	Initialise a server?
 * @param session	The session associated with the given key_state
 */
void key_state_ssl_init(struct key_state_ssl *ks_ssl,
    const struct tls_root_ctx *ssl_ctx, bool is_server, struct tls_session *session) {
	//
	// Setup the data structures
	ASSERT (NULL != ssl_ctx);
	ASSERT (NULL != ks_ssl);
	CLEAR (*ks_ssl);
	//
	// Perform the TLS handshake
	if (starttls (ks_ssl, ssl_ctx, is_server) == false) {
		// Also, ks_ssl->plaintext == ks_ssl->ciphertext == -1
		msg (M_FATAL, "Failed to initialise server context through the TLS Pool");
		return;
	}
}

/**
 * Free the SSL channel part of the given key state.
 *
 * @param ks_ssl	The SSL channel's state info to free
 */
void key_state_ssl_free(struct key_state_ssl *ks_ssl) {
	ASSERT (NULL != ks_ssl);
	if (ks_ssl->plaintext != -1) {
		close (ks_ssl->plaintext);
	}
	if (ks_ssl->ciphertext != -1) {
		close (ks_ssl->ciphertext);
	}
	CLEAR (*ks_ssl);
	ks_ssl->plaintext = ks_ssl->ciphertext = -1;
}

/**************************************************************************/
/** @addtogroup control_tls
 *  @{ */

/** @name Functions for packets to be sent to a remote OpenVPN peer
 *  @{ */

/**
 * Determine if a given socket has something to be read.
 *
 * This is a portable version of the MSG_DONTWAIT behaviour for recv().
 * We could also have set O_NONBLOCK using fcntl() but that would have had
 * to switch between reads and writes, and might have been awkward on a
 * socketpair().  So, instead, we use documented behaviour to poll using
 * select() with a zero timeval.
 */
static bool socket_can_recv (int sox) {
	static struct timeval polltv;
	fd_set rfds;
	FD_ZERO (&rfds);
	FD_SET (sox, &rfds);
	polltv.tv_sec = 0;
	polltv.tv_usec = 0;
	if (select (sox + 1, &rfds, NULL, NULL, &polltv) == 1) {
		return true;
	} else {
		return false;
	}
}

/**
 * Send a buffer's contents to the given socket.
 *
 * @param sox          - The socket to use for sending.
 * @param buf          - The plaintext message to process.
 *
 * @return The return value indicates whether the data was successfully
 *     processed:
 * - \c 1: All the data was processed successfully.
 * - \c 0: The data was not processed, this function should be called
 *   again later to retry.
 * - \c -1: An error occurred.
 */
static int socket_send_buf (int sox, struct buffer *buf) {
	ssize_t wrtn;
	if (sox == -1) {
		// Socket is not properly activated, return error
		return -1;
	}
	if (sox == -1) {
		return -1;
	}
	wrtn = send (sox, buf->data + buf->offset, buf->len, 0);
	if (wrtn == -1) {
		return -1;
	} else if (wrtn < buf->len) {
		buf->offset += wrtn;
		buf->len    -= wrtn;
		return 1;
	} else if (wrtn == buf->len) {
		return 0;
	} else {
		return -1;
	}
}

/**
 * Send a buffer's contents to the given socket.
 *
 * @param sox          - The socket to use for sending.
 * @param buf          - The plaintext message to process.
 * @param maxlen       - The maximum number of bytes to extract.
 *
 * @return The return value indicates whether the data was successfully
 *     processed:
 * - \c 1: All the data was processed successfully.
 * - \c 0: The data was not processed, this function should be called
 *   again later to retry.
 * - \c -1: An error occurred.
 */
static int socket_recv_buf (int sox, struct buffer *buf, int maxlen) {
	ssize_t rcvd;
	if (!socket_can_recv (sox)) {
		return 0;
	}
	buf->offset = 0;
	rcvd = recv (sox, buf->data, maxlen, 0);
	if (rcvd == -1) {
		if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
			// Should only happen with O_NONBLOCK / MSG_DONTWAIT
			return 0;
		} else {
			return -1;
		}
	} else if (rcvd == 0) {
		// Orderly shutdown from the other side
		//TODO// Signal EOF upon reception... is this how?
		buf->len = 0;
		return 1;
	} else if (rcvd > maxlen) {
		// Cry out loud... memory was overlaid
		return -1;
	} else if (rcvd > 0) {
		// Proper delivery of data
		buf->len = rcvd;
		return 1;
	} else {
		// No idea what happened.  Report an error.
		return -1;
	}
}

/**
 * Insert a plaintext buffer into the TLS module.
 *
 * After successfully processing the data, the data in \a buf is zeroized,
 * its length set to zero, and a value of \c 1 is returned.
 *
 * @param ks_ssl       - The security parameter state for this %key
 *                       session.
 * @param buf          - The plaintext message to process.
 *
 * @return The return value indicates whether the data was successfully
 *     processed:
 * - \c 1: All the data was processed successfully.
 * - \c 0: The data was not processed, this function should be called
 *   again later to retry.
 * - \c -1: An error occurred.
 */
int key_state_write_plaintext (struct key_state_ssl *ks_ssl, struct buffer *buf) {
	ASSERT (NULL != ks_ssl);
	ASSERT (NULL != buf);
	return socket_send_buf (ks_ssl->plaintext, buf);
}

/**
 * Insert plaintext data into the TLS module.
 *
 * @param ks_ssl       - The security parameter state for this %key
 *                       session.
 * @param data         - A pointer to the data to process.
 * @param len          - The length in bytes of the data to process.
 *
 * @return The return value indicates whether the data was successfully
 *     processed:
 * - \c 1: All the data was processed successfully.
 * - \c 0: The data was not processed, this function should be called
 *   again later to retry.
 * - \c -1: An error occurred.
 */
int key_state_write_plaintext_const (struct key_state_ssl *ks_ssl,
		const uint8_t *data, int len) {
	struct buffer buf;
	int retval;
	ASSERT (NULL != ks_ssl);
	ASSERT (NULL != data);
	buf.data = (uint8_t *) data;
	buf.offset = 0;
	buf.len = len;
	retval = socket_send_buf (ks_ssl->plaintext, &buf);
	if (buf.offset != 0) {
		// The writing routine may have updated the buffer
		// In lieu of more refined feedback options we return error
		return -1;
	} else {
		return retval;
	}
}

/**
 * Extract ciphertext data from the TLS module.
 *
 * If the \a buf buffer has a length other than zero, this function does
 * not perform any action and returns 0.
 *
 * @param ks_ssl       - The security parameter state for this %key
 *                       session.
 * @param buf          - A buffer in which to store the ciphertext.
 * @param maxlen       - The maximum number of bytes to extract.
 *
 * @return The return value indicates whether the data was successfully
 *     processed:
 * - \c 1: Data was extracted successfully.
 * - \c 0: No data was extracted, this function should be called again
 *   later to retry.
 * - \c -1: An error occurred.
 */
int key_state_read_ciphertext (struct key_state_ssl *ks_ssl, struct buffer *buf,
    int maxlen) {
	ASSERT (NULL != ks_ssl);
	ASSERT (NULL != buf);
	ASSERT (maxlen <= buf->capacity);
	//REALLY?// if (buf.len != 0) {
	//REALLY?// 	return 0;
	//REALLY?// }
	return socket_recv_buf (ks_ssl->ciphertext, buf, maxlen);
}

/** @} name Functions for packets to be sent to a remote OpenVPN peer */


/** @name Functions for packets received from a remote OpenVPN peer
 *  @{ */

/**
 * Insert a ciphertext buffer into the TLS module.
 *
 * After successfully processing the data, the data in \a buf is zeroized,
 * its length set to zero, and a value of \c 1 is returned.
 *
 * @param ks_ssl       - The security parameter state for this %key
 *                       session.
 * @param buf          - The ciphertext message to process.
 *
 * @return The return value indicates whether the data was successfully
 *     processed:
 * - \c 1: All the data was processed successfully.
 * - \c 0: The data was not processed, this function should be called
 *   again later to retry.
 * - \c -1: An error occurred.
 */
int key_state_write_ciphertext (struct key_state_ssl *ks_ssl,
    struct buffer *buf) {
	ASSERT (NULL != ks_ssl);
	ASSERT (NULL != buf);
	return socket_send_buf (ks_ssl->ciphertext, buf);
}

/**
 * Extract plaintext data from the TLS module.
 *
 * If the \a buf buffer has a length other than zero, this function does
 * not perform any action and returns 0.
 *
 * @param ks_ssl       - The security parameter state for this %key
 *                       session.
 * @param buf          - A buffer in which to store the plaintext.
 * @param maxlen       - The maximum number of bytes to extract.
 *
 * @return The return value indicates whether the data was successfully
 *     processed:
 * - \c 1: Data was extracted successfully.
 * - \c 0: No data was extracted, this function should be called again
 *   later to retry.
 * - \c -1: An error occurred.
 */
int key_state_read_plaintext (struct key_state_ssl *ks_ssl, struct buffer *buf,
    int maxlen) {
	ASSERT (NULL != ks_ssl);
	ASSERT (NULL != buf);
	ASSERT (maxlen <= buf->capacity);
	return socket_recv_buf (ks_ssl->plaintext, buf, maxlen);
}

/** @} name Functions for packets received from a remote OpenVPN peer */

/** @} addtogroup control_tls */

/* **************************************
 *
 * Information functions
 *
 * Print information for the end user.
 *
 ***************************************/

/*
 * Print a one line summary of SSL/TLS session handshake.
 */
void print_details (struct key_state_ssl * ks_ssl, const char *prefix) {
	printf ("TLS handshake handling is internal to the TLS Pool\n");
}

/*
 * Show the TLS ciphers that are available for us to use in the OpenSSL
 * library.
 *
 * @param		- list of allowed TLS cipher, or NULL.
 */
void show_available_tls_ciphers (const char *tls_ciphers) {
	printf ("Available cipher suites are internal to the TLS Pool\n");
}

/*
 * Show the available elliptic curves in the crypto library
 */
void show_available_curves (void) {
	printf ("Available curves are internal to the TLS Pool\n");
}

/*
 * The OpenSSL library has a notion of preference in TLS ciphers.  Higher
 * preference == more secure. Return the highest preference cipher.
 */
void get_highest_preference_tls_cipher (char *buf, int size) {
	strncpy (buf, "TLS Pool managed", size);
}

/**
 * Return a pointer to a static memory area containing the
 * name and version number of the SSL library in use
 */
const char *get_ssl_library_version (void) {
	ASSERT (poolfd != -1);
	static struct tlspool_command cmd;
	static char retval [sizeof (cmd.pio_data.pioc_ping.YYYYMMDD_producer)];
	CLEAR (cmd);
	cmd.pio_cmd = PIOC_PING_V1;
	strncpy (cmd.pio_data.pioc_ping.YYYYMMDD_producer,
			TLSPOOL_IDENTITY_V1,
			sizeof (cmd.pio_data.pioc_ping.YYYYMMDD_producer));
	if (send (poolfd, &cmd, sizeof (cmd), 0) == -1) {
		msg (D_TLS_ERRORS, "Failed to send ping to the TLS Pool");
		poolerrno = EIO;
		return NULL;
	}
	if (recv (poolfd, &cmd, sizeof (cmd), 0) == -1) {
		msg (D_TLS_ERRORS, "Failed to receive ping from the TLS Pool");
		poolerrno = EIO;
		return NULL;
	}
	switch (cmd.pio_cmd) {
	case PIOC_PING_V1:
		memcpy (retval,
			cmd.pio_data.pioc_ping.YYYYMMDD_producer,
			sizeof (retval));
		return retval;
	case PIOC_ERROR_V1:
		errno = poolerrno = cmd.pio_data.pioc_error.tlserrno;
		msg (D_TLS_ERRORS, "%s: %s", cmd.pio_data.pioc_error.message, strerror (cmd.pio_data.pioc_error.tlserrno));
		return NULL;
	default:
		poolerrno = EPROTO;
		msg (D_TLS_ERRORS, "Unexpected response while pinging the TLS Pool");
		return NULL;
	}
}

#endif /* defined(ENABLE_CRYPTO) && defined(ENABLE_BACKEND_TLSPOOL) */
