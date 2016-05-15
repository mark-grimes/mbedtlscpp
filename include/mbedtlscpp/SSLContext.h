#ifndef INCLUDEGUARD_mbedtlscpp_SSLContext_h
#define INCLUDEGUARD_mbedtlscpp_SSLContext_h

#include <functional>
#include <system_error>
#include <mbedtls/ssl.h>
//
// Forward declarations
//
namespace mbedtlscpp
{
	class SSLConfig;
	class NetContext;
}


namespace mbedtlscpp
{
	/** @brief Simple wrapper for mbedtls_ssl_context
	 * @author Mark Grimes
	 * @date 14/May/2016
	 * @copyright Apache 2.0 licence (see http://www.apache.org/licenses/LICENSE-2.0)
	 */
	class SSLContext
	{
	public:
		SSLContext();
		virtual ~SSLContext();
		SSLContext( const SSLContext& other ) = delete;
		SSLContext& operator=( const SSLContext& other ) = delete;
		SSLContext( SSLContext&& other ) = default;
		SSLContext& operator=( SSLContext&& other ) = default;

		void setup( const mbedtlscpp::SSLConfig& config, std::error_code& error );
		void setup( const mbedtlscpp::SSLConfig& config );

		void setHostname( const std::string& hostname, std::error_code& error );
		void setHostname( const std::string& hostname );

		void handshake( std::error_code& error );
		void handshake();

		/** @brief Calls mbedtls_ssl_get_verify_result directly on the stored ssl context. */
		int getVerifyResult();

		void setBIO( void* parameter,
		             std::function<int(void*,const unsigned char*,size_t)> sendCallback,
		             std::function<int(void*,unsigned char*,size_t)> receiveCallback,
		             std::function<int(void*,unsigned char*,size_t,uint32_t)> receiveWithTimeoutCallback );

		/** @brief Convenience function (not in mbed tls) that calls setBIO with the defaults
		 * required to use the given net context. */
		void setBIOEasyDefault( mbedtlscpp::NetContext& net );

		/** @brief Write the buffer to the port. Might only do a partial write.
		 *
		 * Calls mbedtls_ssl_write until the result is not MBEDTLS_ERR_SSL_WANT_READ/WRITE or
		 * an error. This could only be a partial write in which case the method should be
		 * called again with pBuffer+bytesWritten and length-bytesWritten. You can use writeAll
		 * to perform this loop for you. */
		size_t write( const unsigned char* pBuffer, size_t length, std::error_code& error );
		size_t write( const unsigned char* pBuffer, size_t length );

		/** @brief Convenience function (not in mbed tls) that loops until all the buffer has been written. */
		void writeAll( const unsigned char* pBuffer, size_t length, std::error_code& error );
		void writeAll( const unsigned char* pBuffer, size_t length );

		size_t read( unsigned char* pBuffer, size_t length, std::error_code& error );
		size_t read( unsigned char* pBuffer, size_t length );

		void closeNotify( std::error_code& error );
		void closeNotify();

		mbedtls_ssl_context* get(){return &context_;} // TODO - remove this once I have a more OO way to use the class
	protected:
		mbedtls_ssl_context context_;
		std::function<int(void*,const unsigned char*,size_t)> sendCallback_;
		std::function<int(void*,unsigned char*,size_t)> receiveCallback_;
		std::function<int(void*,unsigned char*,size_t,uint32_t)> receiveWithTimeoutCallback_;
	};

} // end of namespace mbedtlscpp

#endif // end of include guard
