#ifndef INCLUDEGUARD_mbedtlscpp_mbedtls_error_category_h
#define INCLUDEGUARD_mbedtlscpp_mbedtls_error_category_h

#include <system_error>
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ssl.h"
#include "mbedtls/net.h"

namespace mbedtlscpp
{
	/** @brief error_category class for all errors resulting from mbed tls library calls
	 * @author Mark Grimes
	 * @date 14/May/2016
	 * @copyright Apache 2.0 licence (see http://www.apache.org/licenses/LICENSE-2.0)
	 */
	class mbedtls_error_category : public std::error_category
	{
	public:
		virtual const char* name() const noexcept { return "mbedtlscpp error"; }
		virtual std::string message( int code ) const
		{
			switch( code )
			{
			case 0 :
				return "success";
			case MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED :
				return "MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED";
			case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY :
				return "MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY";
			case MBEDTLS_ERR_X509_BUFFER_TOO_SMALL :
				return "MBEDTLS_ERR_X509_BUFFER_TOO_SMALL";

			// Errors for mbedtls_net_bind
			case MBEDTLS_ERR_NET_SOCKET_FAILED :
				return "MBEDTLS_ERR_NET_SOCKET_FAILED";
			case MBEDTLS_ERR_NET_BIND_FAILED :
				return "MBEDTLS_ERR_NET_BIND_FAILED";
			case MBEDTLS_ERR_NET_LISTEN_FAILED :
				return "MBEDTLS_ERR_NET_LISTEN_FAILED";

			// Errors for mbedtls_net_accept
			case MBEDTLS_ERR_NET_ACCEPT_FAILED :
				return "MBEDTLS_ERR_NET_ACCEPT_FAILED";
			case MBEDTLS_ERR_NET_BUFFER_TOO_SMALL :
				return "MBEDTLS_ERR_NET_BUFFER_TOO_SMALL";
			case MBEDTLS_ERR_SSL_WANT_READ :
				return "MBEDTLS_ERR_SSL_WANT_READ";

			case MBEDTLS_ERR_SSL_ALLOC_FAILED :
				return "MBEDTLS_ERR_SSL_ALLOC_FAILED";

			// Errors for mbedtls_ssl_session_reset
			case MBEDTLS_ERR_SSL_HW_ACCEL_FAILED :
				return "MBEDTLS_ERR_SSL_HW_ACCEL_FAILED";
			case MBEDTLS_ERR_SSL_COMPRESSION_FAILED :
				return "MBEDTLS_ERR_SSL_COMPRESSION_FAILED";

			default :
				return "Unknown error code ("+std::to_string(code)+")";
			}
		}
		static const std::error_category& instance()
		{
			static mbedtls_error_category category;
			return category;
		}
	private:
		mbedtls_error_category() { /* No operation */ }
		mbedtls_error_category( const mbedtls_error_category& other ) = delete;
		mbedtls_error_category& operator=( const mbedtls_error_category& other ) = delete;
		mbedtls_error_category( mbedtls_error_category&& other ) = delete;
		mbedtls_error_category& operator=( mbedtls_error_category&& other ) = delete;
	};

} // end of namespace mbedtlscpp

#endif // end of include guard
