#ifndef INCLUDEGUARD_mbedtlscpp_CtrDRBGContext_h
#define INCLUDEGUARD_mbedtlscpp_CtrDRBGContext_h

#include <string>
#include <system_error>
#include <functional>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include "mbedtlscpp/mbedtls_error_category.h"
#include "mbedtlscpp/EntropyContext.h"
//
// Forward declarations
//
namespace mbedtlscpp
{
	class SSLConfig;
}


namespace mbedtlscpp
{
	/** @brief Simple wrapper for mbedtls_ctr_drbg_context
	 * @author Mark Grimes
	 * @date 15/May/2016
	 * @copyright Apache 2.0 licence (see http://www.apache.org/licenses/LICENSE-2.0)
	 */
	class CtrDRBGContext
	{
	public:
		CtrDRBGContext() { mbedtls_ctr_drbg_init( &context_ ); }
		virtual ~CtrDRBGContext() { mbedtls_ctr_drbg_free( &context_ ); }
		CtrDRBGContext( const CtrDRBGContext& other ) = delete;
		CtrDRBGContext& operator=( const CtrDRBGContext& other ) = delete;
		CtrDRBGContext( CtrDRBGContext&& other ) = default;
		CtrDRBGContext& operator=( CtrDRBGContext&& other ) = default;

		void seed( std::function<int(void*,unsigned char*,size_t)> entropyCallback, void* parameter, const std::string& seedData, std::error_code& error )
		{
			entropyFunction_=entropyCallback;
			int result=mbedtls_ctr_drbg_seed( &context_, *entropyFunction_.target<int(*)(void*,unsigned char*,size_t)>(), parameter, reinterpret_cast<const unsigned char*>(seedData.data()), seedData.size() );
			if( result!=0 ) error.assign( result, mbedtls_error_category::instance() );
		}
		void seed( std::function<int(void*,unsigned char*,size_t)> entropyCallback, void* parameter, const std::string& seedData )
		{
			std::error_code error;
			seed( entropyCallback, parameter, seedData, error );
			if( error ) throw std::system_error( error );
		}

		void seedEasyDefault( mbedtlscpp::EntropyContext& entropy, const std::string& seedData, std::error_code& error )
		{
			seed( mbedtls_entropy_func, &entropy.context_, seedData, error );
		}
		void seedEasyDefault( mbedtlscpp::EntropyContext& entropy, const std::string& seedData )
		{
			std::error_code error;
			seedEasyDefault( entropy, seedData, error );
			if( error ) throw std::system_error( error );
		}

		mbedtls_ctr_drbg_context* get(){return &context_;} // TODO - remove this once I have a more OO way to use the class
	protected:
		friend class SSLConfig;
		mbedtls_ctr_drbg_context context_;
		std::function<int(void*,unsigned char*,size_t)> entropyFunction_;
	};

} // end of namespace mbedtlscpp

#endif // end of include guard
