#ifndef INCLUDEGUARD_mbedtlscpp_EntropyContext_h
#define INCLUDEGUARD_mbedtlscpp_EntropyContext_h

#include <string>
#include <system_error>
#include <mbedtls/entropy.h>
//
// Forward declarations
//
namespace mbedtlscpp
{
	class CtrDRBGContext;
}


namespace mbedtlscpp
{
	/** @brief Simple wrapper for mbedtls_entropy_context
	 * @author Mark Grimes
	 * @date 15/May/2016 */
	class EntropyContext
	{
	public:
		EntropyContext();
		virtual ~EntropyContext();
		EntropyContext( const EntropyContext& other ) = delete;
		EntropyContext& operator=( const EntropyContext& other ) = delete;
		EntropyContext( EntropyContext&& other ) = default;
		EntropyContext& operator=( EntropyContext&& other ) = default;

		mbedtls_entropy_context* get(){return &context_;} // TODO - remove this once I have a more OO way to use the class
	protected:
		friend class mbedtlscpp::CtrDRBGContext;
		mbedtls_entropy_context context_;
	};

} // end of namespace mbedtlscpp

#endif // end of include guard
