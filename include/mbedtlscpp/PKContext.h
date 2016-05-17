#ifndef INCLUDEGUARD_mbedtlscpp_PKContext_h
#define INCLUDEGUARD_mbedtlscpp_PKContext_h

#include <string>
#include <system_error>
#include <mbedtls/net.h>
#include <limits>
#include <vector>
#include "mbedtlscpp/mbedtls_error_category.h"
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
		PKContext() { mbedtls_pk_init( &context_ ); }
		virtual ~PKContext() { mbedtls_pk_free( &context_ ); }
		PKContext( const PKContext& other ) = delete;
		PKContext& operator=( const PKContext& other ) = delete;
		PKContext( PKContext&& other ) = default;
		PKContext& operator=( PKContext&& other ) = default;

		void parseKey( const char* buffer, size_t length, const std::string& password, std::error_code& error )
		{
			const unsigned char* pPassword=nullptr;
			if( !password.empty() ) pPassword=reinterpret_cast<const unsigned char*>(password.data());
			int result=mbedtls_pk_parse_key( &context_, reinterpret_cast<const unsigned char*>(buffer), length, pPassword, password.size() );
			if( result!=0 ) error.assign( result, mbedtls_error_category::instance() );
		}
		void parseKey( const char* buffer, size_t length, const std::string& password )
		{
			std::error_code error;
			parseKey( buffer, length, password, error );
			if( error ) throw std::system_error( error );
		}

		void parseKey( const char* buffer, size_t length, std::error_code& error )
		{
			int result=mbedtls_pk_parse_key( &context_, reinterpret_cast<const unsigned char*>(buffer), length, nullptr, 0 );
			if( result!=0 ) error.assign( result, mbedtls_error_category::instance() );
		}
		void parseKey( const char* buffer, size_t length )
		{
			std::error_code error;
			parseKey( buffer, length, error );
			if( error ) throw std::system_error( error );
		}

		mbedtls_pk_context* get(){return &context_;} // TODO - remove this once I have a more OO way to use the class
	protected:
		friend class mbedtlscpp::SSLConfig;
		mbedtls_pk_context context_;
	};

} // end of namespace mbedtlscpp

#endif // end of include guard
