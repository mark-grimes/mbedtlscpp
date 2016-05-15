#include "mbedtlscpp/PKContext.h"
#include <limits>
#include <vector>
#include "mbedtlscpp/mbedtls_error_category.h"

mbedtlscpp::PKContext::PKContext()
{
	mbedtls_pk_init( &context_ );
}

mbedtlscpp::PKContext::~PKContext()
{
	mbedtls_pk_free( &context_ );
}

void mbedtlscpp::PKContext::parseKey( const char* buffer, size_t length, const std::string& password, std::error_code& error )
{
	const unsigned char* pPassword=nullptr;
	if( !password.empty() ) pPassword=reinterpret_cast<const unsigned char*>(password.data());
	int result=mbedtls_pk_parse_key( &context_, reinterpret_cast<const unsigned char*>(buffer), length, pPassword, password.size() );
	if( result!=0 ) error.assign( result, mbedtls_error_category::instance() );
}

void mbedtlscpp::PKContext::parseKey( const char* buffer, size_t length, const std::string& password )
{
	std::error_code error;
	parseKey( buffer, length, password, error );
	if( error ) throw std::system_error( error );
}

void mbedtlscpp::PKContext::parseKey( const char* buffer, size_t length, std::error_code& error )
{
	int result=mbedtls_pk_parse_key( &context_, reinterpret_cast<const unsigned char*>(buffer), length, nullptr, 0 );
	if( result!=0 ) error.assign( result, mbedtls_error_category::instance() );
}

void mbedtlscpp::PKContext::parseKey( const char* buffer, size_t length )
{
	std::error_code error;
	parseKey( buffer, length, error );
	if( error ) throw std::system_error( error );
}
