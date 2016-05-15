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

void mbedtlscpp::CtrDRBGContext::seed( std::function<int(void*,unsigned char*,size_t)> entropyCallback, void* parameter, const std::string& seedData, std::error_code& error )
{
	entropyFunction_=entropyCallback;
	int result=mbedtls_ctr_drbg_seed( &context_, *entropyFunction_.target<int(*)(void*,unsigned char*,size_t)>(), parameter, reinterpret_cast<const unsigned char*>(seedData.data()), seedData.size() );
	if( result!=0 ) error.assign( result, mbedtls_error_category::instance() );
}

void mbedtlscpp::CtrDRBGContext::seed( std::function<int(void*,unsigned char*,size_t)> entropyCallback, void* parameter, const std::string& seedData )
{
	std::error_code error;
	seed( entropyCallback, parameter, seedData, error );
	if( error ) throw std::system_error( error );
}

void mbedtlscpp::CtrDRBGContext::seedEasyDefault( mbedtlscpp::EntropyContext& entropy, const std::string& seedData, std::error_code& error )
{
	seed( mbedtls_entropy_func, &entropy.context_, seedData, error );
}

void mbedtlscpp::CtrDRBGContext::seedEasyDefault( mbedtlscpp::EntropyContext& entropy, const std::string& seedData )
{
	std::error_code error;
	seedEasyDefault( entropy, seedData, error );
	if( error ) throw std::system_error( error );
}
