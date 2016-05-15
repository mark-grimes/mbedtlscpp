#include "mbedtlscpp/X509Crt.h"
#include <limits>
#include <vector>
#include "mbedtlscpp/mbedtls_error_category.h"

mbedtlscpp::X509Crt::X509Crt()
{
	mbedtls_x509_crt_init( &context_ );
}

mbedtlscpp::X509Crt::~X509Crt()
{
	mbedtls_x509_crt_free( &context_ );
}

unsigned int mbedtlscpp::X509Crt::parseFile( const std::string& filename, std::error_code& error )
{
	int result=mbedtls_x509_crt_parse_file( &context_, filename.c_str() );
	if( result<0 )
	{
		error.assign( result, mbedtls_error_category::instance() );
		return std::numeric_limits<unsigned int>::max(); // Don't know how many failed, so return this as an error value
	}
	return result;
}

unsigned int mbedtlscpp::X509Crt::parseFile( const std::string& filename )
{
	std::error_code error;
	unsigned int failedCertificates=parseFile( filename, error );
	if( error ) throw std::system_error( error );
	return failedCertificates;
}

std::string mbedtlscpp::X509Crt::verifyInfo( int flags, std::error_code& error )
{
	std::string blankString;
	return verifyInfo( flags, blankString, error );
}

std::string mbedtlscpp::X509Crt::verifyInfo( int flags )
{
	std::error_code error;
	std::string result=verifyInfo( flags, error );
	if( error ) throw std::system_error( error );
	return result;
}

std::string mbedtlscpp::X509Crt::verifyInfo( int flags, const std::string& prefix, std::error_code& error )
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

std::string mbedtlscpp::X509Crt::verifyInfo( int flags, const std::string& prefix )
{
	std::error_code error;
	std::string result=verifyInfo( flags, prefix, error );
	if( error ) throw std::system_error( error );
	return result;
}
