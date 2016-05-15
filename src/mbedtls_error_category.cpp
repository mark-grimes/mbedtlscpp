#include "mbedtlscpp/mbedtls_error_category.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ssl.h"


const char* mbedtlscpp::mbedtls_error_category::name() const noexcept
{
	return "mbedtlscpp error";
}

std::string mbedtlscpp::mbedtls_error_category::message( int code ) const
{
	switch( code )
	{
	case 0 :
		return "success";
	case MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED :
		return "MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED";
	case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY :
		return "MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY";
	case MBEDTLS_ERR_X509_BUFFER_TOO_SMALL :
		return "MBEDTLS_ERR_X509_BUFFER_TOO_SMALL";
	default :
		return "Unknown error code ("+std::to_string(code)+")";
	}
}

const std::error_category& mbedtlscpp::mbedtls_error_category::instance()
{
	static mbedtls_error_category category;
	return category;
}

mbedtlscpp::mbedtls_error_category::mbedtls_error_category()
{
	// No operation
}
