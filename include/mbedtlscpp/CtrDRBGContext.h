#ifndef INCLUDEGUARD_mbedtlscpp_CtrDRBGContext_h
#define INCLUDEGUARD_mbedtlscpp_CtrDRBGContext_h

#include <string>
#include <system_error>
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

		void setSeed( const std::string& seedData, mbedtlscpp::EntropyContext& entropy, std::error_code& error );
		void setSeed( const std::string& seedData, mbedtlscpp::EntropyContext& entropy );

		mbedtls_ctr_drbg_context* get(){return &context_;} // TODO - remove this once I have a more OO way to use the class
	protected:
		friend class SSLConfig;
		mbedtls_ctr_drbg_context context_;
	};

} // end of namespace mbedtlscpp

#endif // end of include guard
