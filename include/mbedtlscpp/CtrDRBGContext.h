#ifndef INCLUDEGUARD_mbedtlscpp_CtrDRBGContext_h
#define INCLUDEGUARD_mbedtlscpp_CtrDRBGContext_h

#include <string>
#include <system_error>
#include <functional>
#include <mbedtls/ctr_drbg.h>
//
// Forward declarations
//
namespace mbedtlscpp
{
	class EntropyContext;
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
		CtrDRBGContext();
		virtual ~CtrDRBGContext();
		CtrDRBGContext( const CtrDRBGContext& other ) = delete;
		CtrDRBGContext& operator=( const CtrDRBGContext& other ) = delete;
		CtrDRBGContext( CtrDRBGContext&& other ) = default;
		CtrDRBGContext& operator=( CtrDRBGContext&& other ) = default;

		void seed( std::function<int(void*,unsigned char*,size_t)> entropyCallback, void* parameter, const std::string& seedData, std::error_code& error );
		void seed( std::function<int(void*,unsigned char*,size_t)> entropyCallback, void* parameter, const std::string& seedData );

		void seedEasyDefault( mbedtlscpp::EntropyContext& entropy, const std::string& seedData, std::error_code& error );
		void seedEasyDefault( mbedtlscpp::EntropyContext& entropy, const std::string& seedData );

		mbedtls_ctr_drbg_context* get(){return &context_;} // TODO - remove this once I have a more OO way to use the class
	protected:
		friend class SSLConfig;
		mbedtls_ctr_drbg_context context_;
		std::function<int(void*,unsigned char*,size_t)> entropyFunction_;
	};

} // end of namespace mbedtlscpp

#endif // end of include guard
