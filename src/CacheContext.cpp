#include "mbedtlscpp/CacheContext.h"

mbedtlscpp::CacheContext::CacheContext()
{
	mbedtls_ssl_cache_init( &context_ );
}

mbedtlscpp::CacheContext::~CacheContext()
{
	mbedtls_ssl_cache_free( &context_ );
}
