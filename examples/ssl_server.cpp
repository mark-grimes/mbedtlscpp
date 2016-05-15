/*
 *  SSL server demonstration program
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_fprintf    fprintf
#define mbedtls_printf     printf
#endif

#if !defined(MBEDTLS_BIGNUM_C) || !defined(MBEDTLS_CERTS_C) ||    \
	!defined(MBEDTLS_ENTROPY_C) || !defined(MBEDTLS_SSL_TLS_C) || \
    !defined(MBEDTLS_SSL_SRV_C) || !defined(MBEDTLS_NET_C) || 	\
	!defined(MBEDTLS_RSA_C) || !defined(MBEDTLS_CTR_DRBG_C) ||    \
	!defined(MBEDTLS_X509_CRT_PARSE_C) || !defined(MBEDTLS_FS_IO) || \
	!defined(MBEDTLS_PEM_PARSE_C)
int main( void )
{
	mbedtls_printf("MBEDTLS_BIGNUM_C and/or MBEDTLS_CERTS_C and/or MBEDTLS_ENTROPY_C "
	       "and/or MBEDTLS_SSL_TLS_C and/or MBEDTLS_SSL_SRV_C and/or "
	       "MBEDTLS_NET_C and/or MBEDTLS_RSA_C and/or "
	       "MBEDTLS_CTR_DRBG_C and/or MBEDTLS_X509_CRT_PARSE_C "
	       "and/or MBEDTLS_PEM_PARSE_C not defined.\n");
	return( 0 );
}
#else

#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#endif

#include "mbedtls/certs.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"
#include "mbedtlscpp/NetContext.h"
#include "mbedtlscpp/SSLContext.h"
#include "mbedtlscpp/SSLConfig.h"
#include "mbedtlscpp/EntropyContext.h"
#include "mbedtlscpp/CtrDRBGContext.h"
#include "mbedtlscpp/X509Crt.h"
#include "mbedtlscpp/PKContext.h"

#include <iostream>

#if defined(MBEDTLS_SSL_CACHE_C)
#	include "mbedtlscpp/CacheContext.h"
#endif

#define HTTP_RESPONSE \
	"HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n" \
	"<h2>mbed TLS Test Server</h2>\r\n" \
	"<p>Successful connection using: %s</p>\r\n"

#define DEBUG_LEVEL 0

static void my_debug( void *ctx, int level,
                      const char *file, int line,
                      const char *str )
{
	((void) level);

	mbedtls_fprintf( (FILE *) ctx, "%s:%04d: %s", file, line, str );
	fflush(  (FILE *) ctx  );
}

//void my_debug( void* pStream, int level, const char* file, int line, const char* reason )
//{
//	std::ostream& output=*static_cast<std::ostream*>(pStream);
//	output << file << ":" << line << ": " << reason << std::flush;
//}

int main( void )
{
	int ret, len;
	mbedtlscpp::NetContext listen;
	mbedtlscpp::NetContext client;
	std::error_code error;

	unsigned char buf[1024];
	const char *pers = "ssl_server";

	mbedtlscpp::EntropyContext entropy;
	mbedtlscpp::CtrDRBGContext randGeneratorContext;
	mbedtlscpp::SSLContext sslContext;
	mbedtlscpp::SSLConfig config;

	mbedtlscpp::X509Crt serverCertificate;
	mbedtlscpp::PKContext privateKey;
#if defined(MBEDTLS_SSL_CACHE_C)
	mbedtlscpp::CacheContext cache;
#endif

#if defined(MBEDTLS_DEBUG_C)
	mbedtls_debug_set_threshold( DEBUG_LEVEL );
#endif

	/*
	 * 1. Load the certificates and private RSA key
	 */
	std::cout << "\n  . Loading the server cert. and key..." << std::flush;
	/*
	 * This demonstration program uses embedded test certificates.
	 * Instead, you may want to use mbedtls_x509_crt_parse_file() to read the
	 * server and CA certificates, as well as mbedtls_pk_parse_keyfile().
	 */
	serverCertificate.parse( mbedtls_test_srv_crt, mbedtls_test_srv_crt_len );
	serverCertificate.parse( mbedtls_test_cas_pem, mbedtls_test_cas_pem_len );
	privateKey.parseKey( mbedtls_test_srv_key, mbedtls_test_srv_key_len );
	std::cout << " ok\n";

	/*
	 * 2. Setup the listening TCP socket
	 */
	std::cout << "  . Bind on https://localhost:4433/ ..." << std::flush;
	listen.bind( "", "4433", mbedtlscpp::NetContext::Protocol::TCP );
	std::cout << " ok\n";

	/*
	 * 3. Seed the RNG
	 */
	std::cout << "  . Seeding the random number generator..." << std::flush;
	randGeneratorContext.seedEasyDefault( entropy, pers );
	std::cout << " ok\n";

	/*
	 * 4. Setup stuff
	 */
	std::cout << "  . Setting up the SSL data...." << std::flush;

	config.defaults( mbedtlscpp::SSLConfig::Endpoint::SERVER, mbedtlscpp::SSLConfig::Transport::STREAM, mbedtlscpp::SSLConfig::Preset::DEFAULT );
	config.rngEasyDefault( randGeneratorContext );
	config.dbg( my_debug, stdout );

#if defined(MBEDTLS_SSL_CACHE_C)
	config.sessionCacheEasyDefault( cache );
#endif

//	config.caChain( serverCertificate, nullptr );
	mbedtls_ssl_conf_ca_chain( config.get(), serverCertificate.get()->next, NULL );

	config.ownCert( serverCertificate, privateKey );
	sslContext.setup( config );

	std::cout << " ok\n";

reset:
#ifdef MBEDTLS_ERROR_C
	if( ret != 0 )
	{
		char error_buf[100];
		mbedtls_strerror( ret, error_buf, 100 );
		mbedtls_printf("Last error was: %d - %s\n\n", ret, error_buf );
	}
#endif

	mbedtls_net_free( client.get() );

	sslContext.sessionReset();

	/*
	 * 3. Wait until a client connects
	 */
	std::cout << "  . Waiting for a remote connection ..." << std::flush;
	listen.accept( client );
	sslContext.setBIOEasyDefault( client );
	std::cout << " ok\n";

	/*
	 * 5. Handshake
	 */
	std::cout << "  . Performing the SSL/TLS handshake..." << std::flush;
	sslContext.handshake();
	std::cout << " ok\n";

	/*
	 * 6. Read the HTTP Request
	 */
	std::cout << "  < Read from client:" << std::flush;

	do
	{
		len = sizeof( buf ) - 1;
		memset( buf, 0, sizeof( buf ) );
		ret = mbedtls_ssl_read( sslContext.get(), buf, len );

		if( ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE )
			continue;

		if( ret <= 0 )
		{
			switch( ret )
			{
				case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
					std::cout << " connection was closed gracefully\n";
					break;

				case MBEDTLS_ERR_NET_CONN_RESET:
					std::cout << " connection was reset by peer\n";
					break;

				default:
					std::cout << " mbedtls_ssl_read returned -0x" << std::hex << -ret << std::dec << "\n";
					break;
			}

			break;
		}

		len = ret;
		std::cout << " " << len << " bytes read\n\n" << (char *) buf;

		if( ret > 0 )
			break;
	}
	while( 1 );

	/*
	 * 7. Write the 200 Response
	 */
	std::cout << "  > Write to client:" << std::flush;

	len = sprintf( (char *) buf, HTTP_RESPONSE,
	               mbedtls_ssl_get_ciphersuite( sslContext.get() ) );

	while( ( ret = mbedtls_ssl_write( sslContext.get(), buf, len ) ) <= 0 )
	{
		if( ret == MBEDTLS_ERR_NET_CONN_RESET )
		{
			std::cout << " failed\n  ! peer closed the connection\n\n";
			goto reset;
		}

		if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE )
		{
			std::cout << " failed\n  ! mbedtls_ssl_write returned " << ret << "\n\n";
			goto exit;
		}
	}

	len = ret;
	std::cout << " " << len << " bytes written\n\n" << (char *) buf << "\n";

	std::cout << "  . Closing the connection...";
	sslContext.closeNotify( error );
	if( error )
	{
		std::cout << " failed\n  ! sslContext.closeNotify returned " << error << "\n\n";
		goto reset;
	}
	std::cout << " ok\n";

	ret = 0;
	goto reset;

exit:

#ifdef MBEDTLS_ERROR_C
	if( ret != 0 )
	{
		char error_buf[100];
		mbedtls_strerror( ret, error_buf, 100 );
		mbedtls_printf("Last error was: %d - %s\n\n", ret, error_buf );
	}
#endif

#if defined(_WIN32)
	std::cout << "  Press Enter to exit this program.\n" << std::flush;
	getchar();
#endif

	return( ret );
}
#endif /* MBEDTLS_BIGNUM_C && MBEDTLS_CERTS_C && MBEDTLS_ENTROPY_C &&
          MBEDTLS_SSL_TLS_C && MBEDTLS_SSL_SRV_C && MBEDTLS_NET_C &&
          MBEDTLS_RSA_C && MBEDTLS_CTR_DRBG_C && MBEDTLS_X509_CRT_PARSE_C
          && MBEDTLS_FS_IO && MBEDTLS_PEM_PARSE_C */
