#include "mbedtlscpp/EntropyContext.h"

mbedtlscpp::EntropyContext::EntropyContext()
{
	mbedtls_entropy_init( &context_ );
}

mbedtlscpp::EntropyContext::~EntropyContext()
{
	mbedtls_entropy_free( &context_ );
}
