#ifndef INCLUDEGUARD_mbedtlscpp_X509Crt_h
#define INCLUDEGUARD_mbedtlscpp_X509Crt_h

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
	/** @brief Simple wrapper for mbedtls_x509_crt
	 * @author Mark Grimes
	 * @date 15/May/2016
	 * @copyright Apache 2.0 licence (see http://www.apache.org/licenses/LICENSE-2.0)
	 */
	class X509Crt
	{
	public:
		X509Crt();
		virtual ~X509Crt();
		X509Crt( const X509Crt& other ) = delete;
		X509Crt& operator=( const X509Crt& other ) = delete;
		X509Crt( X509Crt&& other ) = default;
		X509Crt& operator=( X509Crt&& other ) = default;

		unsigned int parseFile( const std::string& filename, std::error_code& error );
		unsigned int parseFile( const std::string& filename );

		static std::string verifyInfo( int flags, std::error_code& error );
		static std::string verifyInfo( int flags );

		static std::string verifyInfo( int flags, const std::string& prefix, std::error_code& error );
		static std::string verifyInfo( int flags, const std::string& prefix );

		mbedtls_x509_crt* get(){return &context_;} // TODO - remove this once I have a more OO way to use the class
	protected:
		friend class mbedtlscpp::SSLConfig;
		mbedtls_x509_crt context_;
	};

} // end of namespace mbedtlscpp

#endif // end of include guard
