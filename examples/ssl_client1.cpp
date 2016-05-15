/** @file
 * @brief An example of using the mbedtlscpp wrappers to contact a remote server.
 *
 * This is basically just the mbed tls ssl_client1 example
 * https://raw.githubusercontent.com/ARMmbed/mbedtls/development/programs/ssl/ssl_client1.c
 * modified to use the C++ wrappers.
 *
 * @author Mark Grimes (from the ARM-copyrighted example)
 * @date 15/May/2016
 * @copyright Apache 2 licence (see http://www.apache.org/licenses/LICENSE-2.0)
 */
#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

//#include "mbedtls/platform.h"
#include "mbedtls/debug.h"
#include "mbedtls/error.h"

#include <cstring>
#include <iostream>
#include "mbedtlscpp/CtrDRBGContext.h"
#include "mbedtlscpp/EntropyContext.h"
#include "mbedtlscpp/SSLContext.h"
#include "mbedtlscpp/SSLConfig.h"
#include "mbedtlscpp/NetContext.h"
#include "mbedtlscpp/X509Crt.h"

#define SERVER_PORT "4433"
#define SERVER_NAME "localhost"
//#define GET_REQUEST "GET / HTTP/1.1\r\nHost: SERVER_NAME\r\n\r\n"
#define GET_REQUEST "GET / HTTP/1.0\r\n\r\n"

#define DEBUG_LEVEL 1

void my_debug( void* pStream, int level, const char* file, int line, const char* reason )
{
	std::ostream& output=*static_cast<std::ostream*>(pStream);
	output << file << ":" << line << ": " << reason << std::flush;
}

int main( void )
{
	try
	{
		int ret, len;
		uint32_t flags;
		unsigned char buf[1024];

		mbedtlscpp::CtrDRBGContext randomNumberContext;
		mbedtlscpp::EntropyContext entropy;
		mbedtlscpp::SSLContext sslContext;
		mbedtlscpp::SSLConfig config;
		mbedtlscpp::NetContext netContext;
		mbedtlscpp::X509Crt caCert;

#		if defined(MBEDTLS_DEBUG_C)
			mbedtls_debug_set_threshold( DEBUG_LEVEL );
#		endif

		/*
		 * 0. Initialize the RNG and the session data
		 */
		std::cout << "\n  . Seeding the random number generator..." << std::flush;
		randomNumberContext.seedEasyDefault( entropy, "ssl_client1" );
		std::cout << " ok\n";

		/*
		 * 0. Initialize certificates
		 */
		std::cout << "  . Loading the CA root certificate ..." << std::flush;
		ret=caCert.parseFile( "/usr/lib/ssl/certs/ca-certificates.crt" );
		//ret=caCert.parseFile( "/home/ubuntu/Communique/test/testData/certificateAuthority_cert.pem" );
		std::cout << " ok (" << ret << " skipped)\n";

		/*
		 * 1. Start the connection
		 */
		std::cout << "  . Connecting to tcp/" << SERVER_NAME << "/" << SERVER_PORT << "..." << std::flush;
		netContext.connect( SERVER_NAME, SERVER_PORT, mbedtlscpp::NetContext::Protocol::TCP );
		std::cout << " ok\n";

		/*
		 * 2. Setup stuff
		 */
		std::cout << "  . Setting up the SSL/TLS structure..." << std::flush;
		config.defaults( mbedtlscpp::SSLConfig::Endpoint::CLIENT, mbedtlscpp::SSLConfig::Transport::STREAM, mbedtlscpp::SSLConfig::Preset::DEFAULT );
		std::cout << " ok\n";

		/* OPTIONAL is not optimal for security,
		 * but makes interop easier in this simplified example */
		config.authMode( mbedtlscpp::SSLConfig::AuthMode::VERIFY_OPTIONAL );
		config.caChain( caCert, nullptr );
		config.rngEasyDefault( randomNumberContext );
		//config.dbg( my_debug, stdout );
		config.dbg( my_debug, &std::cout );

		sslContext.setup( config );
		sslContext.setHostname( SERVER_NAME );
		sslContext.setBIOEasyDefault( netContext );

		/*
		 * 4. Handshake
		 */
		std::cout << "  . Performing the SSL/TLS handshake..." << std::flush;
		sslContext.handshake();
		std::cout << " ok\n";

		/*
		 * 5. Verify the server certificate
		 */
		std::cout << "  . Verifying peer X.509 certificate...";

		/* In real life, we probably want to bail out when ret != 0 */
		if( (flags=sslContext.getVerifyResult()) != 0 )
		{
			std::cout << " failed\n" << caCert.verifyInfo( flags, "  ! " ) << "\n";
		}
		else std::cout << " ok\n";

		/*
		 * 3. Write the GET request
		 */
		std::cout << "  > Write to server:" << std::flush;

		len = sprintf( (char *) buf, GET_REQUEST );

		sslContext.writeAll( buf, len );

		std::cout << " " << len << " bytes written\n\n" << (char *) buf;

		/*
		 * 7. Read the HTTP response
		 */
		std::cout << "  < Read from server:" << std::flush;

		do
		{
			len = sizeof( buf ) - 1;
			memset( buf, 0, sizeof( buf ) );
			std::error_code error;
			ret=sslContext.read( buf, len, error );
			if( error )
			{
				if( error.value()==MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY ) break;
				else throw std::system_error( error );
			}

			if( ret == 0 )
			{
				std::cout << "\n\nEOF\n\n";
				break;
			}

			len = ret;
			std::cout << " " << len << " bytes read\n\n" << (char *) buf;
		}
		while( 1 );

		sslContext.closeNotify();

#ifdef MBEDTLS_ERROR_C
		if( ret != 0 )
		{
			char error_buf[100];
			mbedtls_strerror( ret, error_buf, 100 );
			std::cout << "Last error was: " << ret << " - " << error_buf << "\n\n";
		}
#endif

		return( ret );
	}
	catch( std::exception& error )
	{
		std::cerr << "Exception: " << error.what() << std::endl;
	}
}
