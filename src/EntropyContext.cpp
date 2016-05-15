#include "mbedtlscpp/EntropyContext.h"
#include "mbedtlscpp/mbedtls_error_category.h"

mbedtlscpp::EntropyContext::EntropyContext()
{
	mbedtls_entropy_init( &context_ );
}

mbedtlscpp::EntropyContext::~EntropyContext()
{
	mbedtls_entropy_free( &context_ );
}
