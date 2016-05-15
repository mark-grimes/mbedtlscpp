#include "mbedtlscpp/CtrDRBGContext.h"

#include <mbedtls/entropy.h>
#include "mbedtlscpp/mbedtls_error_category.h"
#include "mbedtlscpp/EntropyContext.h"

mbedtlscpp::CtrDRBGContext::CtrDRBGContext()
{
	mbedtls_ctr_drbg_init( &context_ );
}

mbedtlscpp::CtrDRBGContext::~CtrDRBGContext()
{
	mbedtls_ctr_drbg_free( &context_ );
}

void mbedtlscpp::CtrDRBGContext::setSeed( const std::string& seedData, mbedtlscpp::EntropyContext& entropy, std::error_code& error )
{
	int result=mbedtls_ctr_drbg_seed( &context_, mbedtls_entropy_func, &entropy.context_, reinterpret_cast<const unsigned char*>(seedData.data()), seedData.size() );
	if( result!=0 ) error.assign( result, mbedtls_error_category::instance() );
}

void mbedtlscpp::CtrDRBGContext::setSeed( const std::string& seedData, mbedtlscpp::EntropyContext& entropy )
{
	std::error_code error;
	setSeed( seedData, entropy, error );
	if( error ) throw std::system_error( error );
}

