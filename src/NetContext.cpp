#include "mbedtlscpp/NetContext.h"

#include <vector>
#include "mbedtlscpp/mbedtls_error_category.h"

//
// Use the unnamed namespace for things only used in this file
//
namespace
{
	int rawProtocolCode( mbedtlscpp::NetContext::Protocol protocol )
	{
		switch( protocol )
		{
			case mbedtlscpp::NetContext::Protocol::TCP : return MBEDTLS_NET_PROTO_TCP;
			case mbedtlscpp::NetContext::Protocol::UDP : return MBEDTLS_NET_PROTO_UDP;
		}
	}
} // end of the unnamed namespace

mbedtlscpp::NetContext::NetContext()
{
	mbedtls_net_init( &context_ );
}

mbedtlscpp::NetContext::~NetContext()
{
	mbedtls_net_free( &context_ );
}

void mbedtlscpp::NetContext::connect( const std::string& server, const std::string& port, Protocol protocol, std::error_code& error )
{
	int result=mbedtls_net_connect( &context_, server.c_str(), port.c_str(), rawProtocolCode(protocol) );
	if( result!=0 ) error.assign( result, mbedtls_error_category::instance() );
}

void mbedtlscpp::NetContext::connect( const std::string& server, const std::string& port, Protocol protocol )
{
	std::error_code error;
	connect( server, port, protocol, error );
	if( error ) throw std::system_error( error );
}

void mbedtlscpp::NetContext::bind( const std::string& bindIP, const std::string& port, Protocol protocol, std::error_code& error )
{
	int result=mbedtls_net_bind( &context_, (bindIP.empty() ? nullptr : bindIP.c_str()), port.c_str(), rawProtocolCode(protocol) );
	if( result!=0 ) error.assign( result, mbedtls_error_category::instance() );
}

void mbedtlscpp::NetContext::bind( const std::string& bindIP, const std::string& port, Protocol protocol )
{
	std::error_code error;
	bind( bindIP, port, protocol, error );
	if( error ) throw std::system_error( error );
}

void mbedtlscpp::NetContext::accept( mbedtlscpp::NetContext& clientContext, std::error_code& error )
{
	// TODO - Figure out if I should free the clientContext first
	int result=mbedtls_net_accept( &context_, &clientContext.context_, nullptr, 0, nullptr );
	if( result!=0 ) error.assign( result, mbedtls_error_category::instance() );
}

void mbedtlscpp::NetContext::accept( mbedtlscpp::NetContext& clientContext )
{
	std::error_code error;
	accept( clientContext, error );
	if( error ) throw std::system_error( error );
}

void mbedtlscpp::NetContext::accept( mbedtlscpp::NetContext& clientContext, std::string& clientIPAddress, std::error_code& error )
{
	// TODO - Figure out if I should free the clientContext first
	// TODO - Figure out if this is non-blocking and the buffer needs to be kept alive somewhere
	std::vector<char> buffer(128);
	size_t bytesWritten;
	int result=mbedtls_net_accept( &context_, &clientContext.context_, buffer.data(), buffer.size(), &bytesWritten );
	clientIPAddress.assign( buffer.data(), bytesWritten );
	if( result!=0 ) error.assign( result, mbedtls_error_category::instance() );
}

void mbedtlscpp::NetContext::accept( mbedtlscpp::NetContext& clientContext, std::string& clientIPAddress )
{
	std::error_code error;
	accept( clientContext, clientIPAddress, error );
	if( error ) throw std::system_error( error );
}
