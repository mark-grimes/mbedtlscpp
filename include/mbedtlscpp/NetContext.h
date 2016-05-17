#ifndef INCLUDEGUARD_mbedtlscpp_NetContext_h
#define INCLUDEGUARD_mbedtlscpp_NetContext_h

#include <string>
#include <system_error>
#include <mbedtls/net.h>
#include <vector>
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
		NetContext() { mbedtls_net_init( &context_ ); }
		virtual ~NetContext() { mbedtls_net_free( &context_ ); }
		NetContext( const NetContext& other ) = delete;
		NetContext& operator=( const NetContext& other ) = delete;
		NetContext( NetContext&& other ) = default;
		NetContext& operator=( NetContext&& other ) = default;

		void connect( const std::string& server, const std::string& port, Protocol protocol, std::error_code& error )
		{
			int result=mbedtls_net_connect( &context_, server.c_str(), port.c_str(), rawProtocolCode(protocol) );
			if( result!=0 ) error.assign( result, mbedtls_error_category::instance() );
		}
		void connect( const std::string& server, const std::string& port, Protocol protocol )
		{
			std::error_code error;
			connect( server, port, protocol, error );
			if( error ) throw std::system_error( error );
		}

		void bind( const std::string& bindIP, const std::string& port, Protocol protocol, std::error_code& error )
		{
			int result=mbedtls_net_bind( &context_, (bindIP.empty() ? nullptr : bindIP.c_str()), port.c_str(), rawProtocolCode(protocol) );
			if( result!=0 ) error.assign( result, mbedtls_error_category::instance() );
		}
		void bind( const std::string& bindIP, const std::string& port, Protocol protocol )
		{
			std::error_code error;
			bind( bindIP, port, protocol, error );
			if( error ) throw std::system_error( error );
		}

		void accept( mbedtlscpp::NetContext& clientContext, std::error_code& error )
		{
			// TODO - Figure out if I should free the clientContext first
			int result=mbedtls_net_accept( &context_, &clientContext.context_, nullptr, 0, nullptr );
			if( result!=0 ) error.assign( result, mbedtls_error_category::instance() );
		}
		void accept( mbedtlscpp::NetContext& clientContext )
		{
			std::error_code error;
			accept( clientContext, error );
			if( error ) throw std::system_error( error );
		}

		void accept( mbedtlscpp::NetContext& clientContext, std::string& clientIPAddress, std::error_code& error )
		{
			// TODO - Figure out if I should free the clientContext first
			// TODO - Figure out if this is non-blocking and the buffer needs to be kept alive somewhere
			std::vector<char> buffer(128);
			size_t bytesWritten;
			int result=mbedtls_net_accept( &context_, &clientContext.context_, buffer.data(), buffer.size(), &bytesWritten );
			clientIPAddress.assign( buffer.data(), bytesWritten );
			if( result!=0 ) error.assign( result, mbedtls_error_category::instance() );
		}
		void accept( mbedtlscpp::NetContext& clientContext, std::string& clientIPAddress )
		{
			std::error_code error;
			accept( clientContext, clientIPAddress, error );
			if( error ) throw std::system_error( error );
		}


		mbedtls_net_context* get(){return &context_;} // TODO - remove this once I have a more OO way to use the class
	protected:
		friend class mbedtlscpp::SSLContext;
		mbedtls_net_context context_;
		static int rawProtocolCode( mbedtlscpp::NetContext::Protocol protocol )
		{
			switch( protocol )
			{
				case mbedtlscpp::NetContext::Protocol::TCP : return MBEDTLS_NET_PROTO_TCP;
				case mbedtlscpp::NetContext::Protocol::UDP : return MBEDTLS_NET_PROTO_UDP;
			}
		}
	};

} // end of namespace mbedtlscpp

#endif // end of include guard
