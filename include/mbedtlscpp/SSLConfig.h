#ifndef INCLUDEGUARD_mbedtlscpp_SSLConfig_h
#define INCLUDEGUARD_mbedtlscpp_SSLConfig_h

#include <string>
#include <system_error>
#include <functional>
#include <mbedtls/ssl.h>
//
// Forward declarations
//
namespace mbedtlscpp
{
	class SSLContext;
	class X509Crt;
	class CtrDRBGContext;
	class PKContext;
}


namespace mbedtlscpp
{
	/** @brief Simple wrapper for mbedtls_ssl_config
	 *
	 * Note that as well as storing the underlying mbed tls context handle, it also takes copies of
	 * the callback functions set. This is necessary since complex std::function objects with internal
	 * state could be created instead of just plain function pointers. As a consequence, this means
	 * that the instance must be kept alive even after being applied to the SSL context (this might
	 * be the case anyway).
	 *
	 * @author Mark Grimes
	 * @date 14/May/2016
	 * @copyright Apache 2.0 licence (see http://www.apache.org/licenses/LICENSE-2.0)
	 */
	class SSLConfig
	{
	public:
		enum class Endpoint{ CLIENT, SERVER };
		enum class Transport{ STREAM, DATAGRAM };
		enum class Preset{ DEFAULT };
		enum class AuthMode{ VERIFY_NONE, VERIFY_OPTIONAL, VERIFY_REQUIRED };
	public:
		SSLConfig();
		virtual ~SSLConfig();
		SSLConfig( const SSLConfig& other ) = delete;
		SSLConfig& operator=( const SSLConfig& other ) = delete;
		SSLConfig( SSLConfig&& other ) = default;
		SSLConfig& operator=( SSLConfig&& other ) = default;

		void caChain( mbedtlscpp::X509Crt& certificateChain, mbedtls_x509_crl* pRevocationList );

		void ownCert( mbedtlscpp::X509Crt& ownCertificate, mbedtlscpp::PKContext& privateKey, std::error_code& error );
		void ownCert( mbedtlscpp::X509Crt& ownCertificate, mbedtlscpp::PKContext& privateKey );

		void defaults( Endpoint endpoint, Transport transport, Preset preset, std::error_code& error );
		void defaults( Endpoint endpoint, Transport transport, Preset preset );

		void authMode( AuthMode authMode );

		void rng( std::function<int(void*,unsigned char*,size_t)> generator, void* parameter );
		/** @brief Convenience function that calls rng with the defaults required to use ctr_drbg generator. */
		void rngEasyDefault( CtrDRBGContext& ctrDrbgContext );

		void dbg( std::function<void(void*,int,const char*,int,const char*)> debugCallback, void* parameter );

		mbedtls_ssl_config* get(){return &context_;} // TODO - remove this once I have a more OO way to use the class
	protected:
		friend class mbedtlscpp::SSLContext;
		mbedtls_ssl_config context_;
		std::function<int(void*,unsigned char*,size_t)> randomNumberGenerator_;
		std::function<void(void*,int,const char*,int,const char*)> debugCallback_;
	};

} // end of namespace mbedtlscpp

#endif // end of include guard
