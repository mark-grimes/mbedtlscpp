#ifndef INCLUDEGUARD_mbedtlscpp_mbedtls_error_category_h
#define INCLUDEGUARD_mbedtlscpp_mbedtls_error_category_h

#include <system_error>

namespace mbedtlscpp
{
	/** @brief error_category class for all errors resulting from mbed tls library calls
	 * @author Mark Grimes
	 * @date 14/May/2016
	 */
	class mbedtls_error_category : public std::error_category
	{
	public:
		virtual const char* name() const noexcept;
		virtual std::string message( int code ) const;
		static const std::error_category& instance();
	private:
		mbedtls_error_category();
		mbedtls_error_category( const mbedtls_error_category& other ) = delete;
		mbedtls_error_category& operator=( const mbedtls_error_category& other ) = delete;
		mbedtls_error_category( mbedtls_error_category&& other ) = delete;
		mbedtls_error_category& operator=( mbedtls_error_category&& other ) = delete;
	};

} // end of namespace mbedtlscpp

#endif // end of include guard
