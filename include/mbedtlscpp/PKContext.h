#ifndef INCLUDEGUARD_mbedtlscpp_PKContext_h
#define INCLUDEGUARD_mbedtlscpp_PKContext_h

#include <string>
#include <system_error>
#include <mbedtls/net.h>
//
// Forward declarations
//
namespace mbedtlscpp
{
	class SSLConfig;
}

namespace mbedtlscpp
{
	/** @brief Simple wrapper for mbedtls_pk_context (i.e. private keys).
	 * @author Mark Grimes
	 * @date 15/May/2016
	 * @copyright Apache 2.0 licence (see http://www.apache.org/licenses/LICENSE-2.0)
	 */
	class PKContext
	{
	public:
		PKContext();
		virtual ~PKContext();
		PKContext( const PKContext& other ) = delete;
		PKContext& operator=( const PKContext& other ) = delete;
		PKContext( PKContext&& other ) = default;
		PKContext& operator=( PKContext&& other ) = default;

		void parseKey( const char* buffer, size_t length, const std::string& password, std::error_code& error );
		void parseKey( const char* buffer, size_t length, const std::string& password );

		void parseKey( const char* buffer, size_t length, std::error_code& error );
		void parseKey( const char* buffer, size_t length );

		mbedtls_pk_context* get(){return &context_;} // TODO - remove this once I have a more OO way to use the class
	protected:
		friend class mbedtlscpp::SSLConfig;
		mbedtls_pk_context context_;
	};

} // end of namespace mbedtlscpp

#endif // end of include guard
