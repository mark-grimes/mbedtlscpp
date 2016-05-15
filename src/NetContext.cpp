#include "mbedtlscpp/NetContext.h"

#include "mbedtlscpp/mbedtls_error_category.h"


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
	int proto;
	switch( protocol )
	{
		case Protocol::TCP : proto=MBEDTLS_NET_PROTO_TCP; break;
		case Protocol::UDP : proto=MBEDTLS_NET_PROTO_UDP; break;
	}
	int result=mbedtls_net_connect( &context_, server.c_str(), port.c_str(), proto );
	if( result!=0 ) error.assign( result, mbedtls_error_category::instance() );
}

void mbedtlscpp::NetContext::connect( const std::string& server, const std::string& port, Protocol protocol )
{
	std::error_code error;
	connect( server, port, protocol, error );
	if( error ) throw std::system_error( error );
}
