#ifndef INCLUDEGUARD_mbedtlscpp_X509Crt_h
#define INCLUDEGUARD_mbedtlscpp_X509Crt_h

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
	/** @brief Simple wrapper for mbedtls_x509_crt
	 * @author Mark Grimes
	 * @date 15/May/2016
	 * @copyright Apache 2.0 licence (see http://www.apache.org/licenses/LICENSE-2.0)
	 */
	class X509Crt
	{
	public:
		X509Crt() { mbedtls_x509_crt_init( &context_ ); }
		virtual ~X509Crt() { mbedtls_x509_crt_free( &context_ ); }
		X509Crt( const X509Crt& other ) = delete;
		X509Crt& operator=( const X509Crt& other ) = delete;
		X509Crt( X509Crt&& other ) = default;
		X509Crt& operator=( X509Crt&& other ) = default;

		unsigned int parse( const char* buffer, size_t length, std::error_code& error )
		{
			int result=mbedtls_x509_crt_parse( &context_, reinterpret_cast<const unsigned char*>(buffer), length );
			if( result<0 )
			{
				error.assign( result, mbedtls_error_category::instance() );
				return std::numeric_limits<unsigned int>::max(); // Don't know how many failed, so return this as an error value
			}
			return result;
		}
		unsigned int parse( const char* buffer, size_t length )
		{
			std::error_code error;
			unsigned int failedCertificates=parse( buffer, length, error );
			if( error ) throw std::system_error( error );
			return failedCertificates;
		}

		unsigned int parseFile( const std::string& filename, std::error_code& error )
		{
			int result=mbedtls_x509_crt_parse_file( &context_, filename.c_str() );
			if( result<0 )
			{
				error.assign( result, mbedtls_error_category::instance() );
				return std::numeric_limits<unsigned int>::max(); // Don't know how many failed, so return this as an error value
			}
			return result;
		}
		unsigned int parseFile( const std::string& filename )
		{
			std::error_code error;
			unsigned int failedCertificates=parseFile( filename, error );
			if( error ) throw std::system_error( error );
			return failedCertificates;
		}

		static std::string verifyInfo( int flags, std::error_code& error )
		{
			std::string blankString;
			return verifyInfo( flags, blankString, error );
		}
		static std::string verifyInfo( int flags )
		{
			std::error_code error;
			std::string result=verifyInfo( flags, error );
			if( error ) throw std::system_error( error );
			return result;
		}

		static std::string verifyInfo( int flags, const std::string& prefix, std::error_code& error )
		{
			std::vector<char> buffer(128);
			int bytesWritten=mbedtls_x509_crt_verify_info( buffer.data(), buffer.size(), prefix.c_str(), flags );
			// If the buffer is completely filled, enlarge it and try again
			while( bytesWritten==MBEDTLS_ERR_X509_BUFFER_TOO_SMALL )
			{
				buffer.resize( buffer.size()*2 );
				bytesWritten=mbedtls_x509_crt_verify_info( buffer.data(), buffer.size(), prefix.c_str(), flags );
			}
			if( bytesWritten<0 )
			{
				error.assign( bytesWritten, mbedtls_error_category::instance() );
				return "verifyInfo error - see error code";
			}
			return std::string( buffer.data(), bytesWritten );
		}
		static std::string verifyInfo( int flags, const std::string& prefix )
		{
			std::error_code error;
			std::string result=verifyInfo( flags, prefix, error );
			if( error ) throw std::system_error( error );
			return result;
		}

		mbedtls_x509_crt* get(){return &context_;} // TODO - remove this once I have a more OO way to use the class
	protected:
		friend class mbedtlscpp::SSLConfig;
		mbedtls_x509_crt context_;
	};

} // end of namespace mbedtlscpp

#endif // end of include guard
