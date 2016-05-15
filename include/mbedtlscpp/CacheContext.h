#ifndef INCLUDEGUARD_mbedtlscpp_CacheContext_h
#define INCLUDEGUARD_mbedtlscpp_CacheContext_h

#include <mbedtls/ssl_cache.h>
//
// Forward declarations
//
namespace mbedtlscpp
{
	class SSLConfig;
}


namespace mbedtlscpp
{
	/** @brief Simple wrapper for mbedtls_ssl_cache_context
	 * @author Mark Grimes
	 * @date 15/May/2016
	 * @copyright Apache 2.0 licence (see http://www.apache.org/licenses/LICENSE-2.0)
	 */
	class CacheContext
	{
	public:
		CacheContext();
		virtual ~CacheContext();
		CacheContext( const CacheContext& other ) = delete;
		CacheContext& operator=( const CacheContext& other ) = delete;
		CacheContext( CacheContext&& other ) = default;
		CacheContext& operator=( CacheContext&& other ) = default;

		mbedtls_ssl_cache_context* get(){return &context_;} // TODO - remove this once I have a more OO way to use the class
	protected:
		friend class mbedtlscpp::SSLConfig;
		mbedtls_ssl_cache_context context_;
	};

} // end of namespace mbedtlscpp

#endif // end of include guard
