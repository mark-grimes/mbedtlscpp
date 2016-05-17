#ifndef INCLUDEGUARD_mbedtlscpp_EntropyContext_h
#define INCLUDEGUARD_mbedtlscpp_EntropyContext_h

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
	 * @date 15/May/2016
	 * @copyright Apache 2.0 licence (see http://www.apache.org/licenses/LICENSE-2.0)
	 */
	class EntropyContext
	{
	public:
		EntropyContext() { mbedtls_entropy_init( &context_ ); }
		virtual ~EntropyContext() { mbedtls_entropy_free( &context_ ); }
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
