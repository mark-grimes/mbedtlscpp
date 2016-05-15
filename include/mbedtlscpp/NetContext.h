#ifndef INCLUDEGUARD_mbedtlscpp_NetContext_h
#define INCLUDEGUARD_mbedtlscpp_NetContext_h

#include <string>
#include <system_error>
#include <mbedtls/net.h>
//
// Forward declarations
//
namespace mbedtlscpp
{
	class SSLContext;
}


namespace mbedtlscpp
{
	/** @brief Simple wrapper for mbedtls_net_context
	 * @author Mark Grimes
	 * @date 15/May/2016
	 * @copyright Apache 2.0 licence (see http://www.apache.org/licenses/LICENSE-2.0)
	 */
	class NetContext
	{
	public:
		enum class Protocol{ TCP, UDP };
	public:
		NetContext();
		virtual ~NetContext();
		NetContext( const NetContext& other ) = delete;
		NetContext& operator=( const NetContext& other ) = delete;
		NetContext( NetContext&& other ) = default;
		NetContext& operator=( NetContext&& other ) = default;

		void connect( const std::string& server, const std::string& port, Protocol protocol, std::error_code& error );
		void connect( const std::string& server, const std::string& port, Protocol protocol );

		void bind( const std::string& bindIP, const std::string& port, Protocol protocol, std::error_code& error );
		void bind( const std::string& bindIP, const std::string& port, Protocol protocol );

		void accept( mbedtlscpp::NetContext& clientContext, std::error_code& error );
		void accept( mbedtlscpp::NetContext& clientContext );

		void accept( mbedtlscpp::NetContext& clientContext, std::string& clientIPAddress, std::error_code& error );
		void accept( mbedtlscpp::NetContext& clientContext, std::string& clientIPAddress );


		mbedtls_net_context* get(){return &context_;} // TODO - remove this once I have a more OO way to use the class
	protected:
		friend class mbedtlscpp::SSLContext;
		mbedtls_net_context context_;
	};

} // end of namespace mbedtlscpp

#endif // end of include guard
