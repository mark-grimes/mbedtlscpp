#ifndef INCLUDEGUARD_mbedtlscpp_SSLConfig_h
#define INCLUDEGUARD_mbedtlscpp_SSLConfig_h

#include <string>
#include <system_error>
#include <functional>
#include <mbedtls/ssl.h>
#include "mbedtlscpp/X509Crt.h"
#include "mbedtlscpp/PKContext.h"
#include "mbedtlscpp/CtrDRBGContext.h"
#include "mbedtlscpp/CacheContext.h"
#include "mbedtlscpp/mbedtls_error_category.h"
//
// Forward declarations
//
namespace mbedtlscpp
{
	class SSLContext;
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
		SSLConfig() { mbedtls_ssl_config_init( &context_ ); }
		virtual ~SSLConfig() { mbedtls_ssl_config_free( &context_ ); }
		SSLConfig( const SSLConfig& other ) = delete;
		SSLConfig& operator=( const SSLConfig& other ) = delete;
		SSLConfig( SSLConfig&& other ) = default;
		SSLConfig& operator=( SSLConfig&& other ) = default;

		void caChain( mbedtlscpp::X509Crt& certificateChain, mbedtls_x509_crl* pRevocationList )
		{
			mbedtls_ssl_conf_ca_chain( &context_, &certificateChain.context_, pRevocationList );
		}

		void ownCert( mbedtlscpp::X509Crt& ownCertificate, mbedtlscpp::PKContext& privateKey, std::error_code& error )
		{
			int result=mbedtls_ssl_conf_own_cert( &context_, &ownCertificate.context_, &privateKey.context_ );
			if( result!=0 ) error.assign( result, mbedtls_error_category::instance() );
		}
		void ownCert( mbedtlscpp::X509Crt& ownCertificate, mbedtlscpp::PKContext& privateKey )
		{
			std::error_code error;
			ownCert( ownCertificate, privateKey, error );
			if( error ) throw std::system_error( error );
		}

		void defaults( Endpoint endpoint, Transport transport, Preset preset, std::error_code& error )
		{
			int end, trans, pre;
			switch( endpoint )
			{
				case Endpoint::CLIENT : end=MBEDTLS_SSL_IS_CLIENT; break;
				case Endpoint::SERVER : end=MBEDTLS_SSL_IS_SERVER; break;
			}
			switch( transport )
			{
				case Transport::STREAM : trans=MBEDTLS_SSL_TRANSPORT_STREAM; break;
				case Transport::DATAGRAM : trans=MBEDTLS_SSL_TRANSPORT_DATAGRAM; break;
			}
			switch( preset )
			{
				case Preset::DEFAULT : pre=MBEDTLS_SSL_PRESET_DEFAULT; break;
				default :
					throw std::runtime_error( "mbedtlscpp::SSLConfig::defaults not coded that Preset value yet" );
			}

			int result=mbedtls_ssl_config_defaults( &context_, end, trans, pre );
			if( result!=0 ) error.assign( result, mbedtls_error_category::instance() );
		}
		void defaults( Endpoint endpoint, Transport transport, Preset preset )
		{
			std::error_code error;
			defaults( endpoint, transport, preset, error );
			if( error ) throw std::system_error( error );
		}

		void authMode( AuthMode authMode )
		{
			int mode;
			switch( authMode )
			{
			case AuthMode::VERIFY_NONE : mode=MBEDTLS_SSL_VERIFY_NONE; break;
			case AuthMode::VERIFY_OPTIONAL : mode=MBEDTLS_SSL_VERIFY_OPTIONAL; break;
			case AuthMode::VERIFY_REQUIRED : mode=MBEDTLS_SSL_VERIFY_REQUIRED; break;
			}
			mbedtls_ssl_conf_authmode( &context_, mode );
		}

		void rng( std::function<int(void*,unsigned char*,size_t)> generator, void* parameter )
		{
			randomNumberGenerator_=generator;
			mbedtls_ssl_conf_rng( &context_, *randomNumberGenerator_.target<int(*)(void*,unsigned char*,size_t)>(), parameter );
		}
		/** @brief Convenience function that calls rng with the defaults required to use ctr_drbg generator. */
		void rngEasyDefault( CtrDRBGContext& ctrDrbgContext )
		{
			rng( mbedtls_ctr_drbg_random, &ctrDrbgContext.context_ );
		}

		void sessionCache( void* parameter, std::function<int(void*,mbedtls_ssl_session*)> cacheGet, std::function<int(void*,const mbedtls_ssl_session*)> cacheSet )
		{
			cacheGet_=cacheGet;
			cacheSet_=cacheSet;
			mbedtls_ssl_conf_session_cache( &context_, parameter, *cacheGet_.target<int(*)(void*,mbedtls_ssl_session*)>(), *cacheSet_.target<int(*)(void*,const mbedtls_ssl_session*)>() );
		}
		/** @brief Convenience function that calls sessionCache with the defaults required for the default cache. */
		void sessionCacheEasyDefault( mbedtlscpp::CacheContext& cache )
		{
			sessionCache( &cache.context_, mbedtls_ssl_cache_get, mbedtls_ssl_cache_set );
		}

		void dbg( std::function<void(void*,int,const char*,int,const char*)> debugCallback, void* parameter )
		{
			debugCallback_=debugCallback;
			mbedtls_ssl_conf_dbg( &context_, *debugCallback_.target<void(*)(void*,int,const char*,int,const char*)>(), parameter );
		}

		mbedtls_ssl_config* get(){return &context_;} // TODO - remove this once I have a more OO way to use the class
	protected:
		friend class mbedtlscpp::SSLContext;
		mbedtls_ssl_config context_;
		std::function<int(void*,unsigned char*,size_t)> randomNumberGenerator_;
		std::function<void(void*,int,const char*,int,const char*)> debugCallback_;
		std::function<int(void*,mbedtls_ssl_session*)> cacheGet_;
		std::function<int(void*,const mbedtls_ssl_session*)> cacheSet_;
	};

} // end of namespace mbedtlscpp

#endif // end of include guard
