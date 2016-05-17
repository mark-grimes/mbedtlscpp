#ifndef INCLUDEGUARD_mbedtlscpp_SSLContext_h
#define INCLUDEGUARD_mbedtlscpp_SSLContext_h

#include <functional>
#include <system_error>
#include <mbedtls/ssl.h>
#include "mbedtlscpp/mbedtls_error_category.h"
#include "mbedtlscpp/SSLConfig.h"
#include "mbedtlscpp/NetContext.h"


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
		SSLContext() { mbedtls_ssl_init(&context_); }
		virtual ~SSLContext() { mbedtls_ssl_free(&context_); }
		SSLContext( const SSLContext& other ) = delete;
		SSLContext& operator=( const SSLContext& other ) = delete;
		SSLContext( SSLContext&& other ) = default;
		SSLContext& operator=( SSLContext&& other ) = default;

		void setup( const mbedtlscpp::SSLConfig& config, std::error_code& error )
		{
			int result=mbedtls_ssl_setup( &context_, &config.context_ );
			if( result!=0 ) error.assign( result, mbedtls_error_category::instance() );
		}
		void setup( const mbedtlscpp::SSLConfig& config )
		{
			std::error_code error;
			setup( config, error );
			if( error ) throw std::system_error( error );
		}

		void setHostname( const std::string& hostname, std::error_code& error )
		{
			int result=mbedtls_ssl_set_hostname( &context_, hostname.c_str() );
			if( result!=0 ) error.assign( result, mbedtls_error_category::instance() );
		}
		void setHostname( const std::string& hostname )
		{
			std::error_code error;
			setHostname( hostname, error );
			if( error ) throw std::system_error( error );
		}

		void handshake( std::error_code& error )
		{
			int result;
			while( ( result=mbedtls_ssl_handshake(&context_) ) != 0 )
			{
				if( result!=MBEDTLS_ERR_SSL_WANT_READ && result!=MBEDTLS_ERR_SSL_WANT_WRITE )
				{
					error.assign( result, mbedtls_error_category::instance() );
					return;
				}
			}
		}
		void handshake()
		{
			std::error_code error;
			handshake( error );
			if( error ) throw std::system_error( error );
		}

		/** @brief Calls mbedtls_ssl_get_verify_result directly on the stored ssl context. */
		int getVerifyResult()
		{
			return mbedtls_ssl_get_verify_result( &context_ );
		}

		void setBIO( void* parameter,
		             std::function<int(void*,const unsigned char*,size_t)> sendCallback,
		             std::function<int(void*,unsigned char*,size_t)> receiveCallback,
		             std::function<int(void*,unsigned char*,size_t,uint32_t)> receiveWithTimeoutCallback )
		{
			sendCallback_=sendCallback;
			receiveCallback_=receiveCallback;
			receiveWithTimeoutCallback_=receiveWithTimeoutCallback;

			// Get the raw function pointers back out so that I can pass them to the mbed tls function.
			// Note that it's valid for some of these to be null.
			auto rawSend=sendCallback_.target<int(*)(void*,const unsigned char*,size_t)>();
			auto rawRec=receiveCallback_.target<int(*)(void*,unsigned char*,size_t)>();
			auto rawRecTime=receiveWithTimeoutCallback_.target<int(*)(void*,unsigned char*,size_t,uint32_t)>();

			// Only dereference if the pointers are not null
			mbedtls_ssl_set_bio( &context_, parameter, (rawSend ? *rawSend : nullptr), (rawRec ? *rawRec : nullptr), (rawRecTime ? *rawRecTime : nullptr) );
		}

		/** @brief Convenience function (not in mbed tls) that calls setBIO with the defaults
		 * required to use the given net context. */
		void setBIOEasyDefault( mbedtlscpp::NetContext& net )
		{
			setBIO( &net.context_, mbedtls_net_send, mbedtls_net_recv, nullptr );
		}

		/** @brief Write the buffer to the port. Might only do a partial write.
		 *
		 * Calls mbedtls_ssl_write until the result is not MBEDTLS_ERR_SSL_WANT_READ/WRITE or
		 * an error. This could only be a partial write in which case the method should be
		 * called again with pBuffer+bytesWritten and length-bytesWritten. You can use writeAll
		 * to perform this loop for you. */
		size_t write( const unsigned char* pBuffer, size_t length, std::error_code& error )
		{
			int result;
			while( (result=mbedtls_ssl_write(&context_,pBuffer,length)) < 0 )
			{
				// If result is MBEDTLS_ERR_SSL_WANT_READ/WRITE then we need to call again with the same arguments
				if( result!=MBEDTLS_ERR_SSL_WANT_READ && result!=MBEDTLS_ERR_SSL_WANT_WRITE )
				{
					error.assign( result, mbedtls_error_category::instance() );
					return 0;
				}
			}
			return result;
		}
		size_t write( const unsigned char* pBuffer, size_t length )
		{
			std::error_code error;
			size_t bytesWritten=write( pBuffer, length, error );
			if( error ) throw std::system_error( error );
			return bytesWritten;
		}

		/** @brief Convenience function (not in mbed tls) that loops until all the buffer has been written. */
		void writeAll( const unsigned char* pBuffer, size_t length, std::error_code& error )
		{
			while( length>0 )
			{
				size_t bytesWritten=write( pBuffer, length, error );
				if( error ) return;
				pBuffer+=bytesWritten;
				length-=bytesWritten;
			}
		}
		void writeAll( const unsigned char* pBuffer, size_t length )
		{
			std::error_code error;
			writeAll( pBuffer, length, error );
			if( error ) throw std::system_error( error );
		}

		size_t read( unsigned char* pBuffer, size_t length, std::error_code& error )
		{
			int result;
			while( (result=mbedtls_ssl_read(&context_,pBuffer,length)) < 0 )
			{
				if( result<0 && result!=MBEDTLS_ERR_SSL_WANT_READ && result!=MBEDTLS_ERR_SSL_WANT_WRITE )
				{
					error.assign( result, mbedtls_error_category::instance() );
					return 0;
				}
			}
			return result;
		}
		size_t read( unsigned char* pBuffer, size_t length )
		{
			std::error_code error;
			size_t bytesRead=read( pBuffer, length, error );
			if( error ) throw std::system_error( error );
			return bytesRead;
		}

		void sessionReset( std::error_code& error )
		{
			int result=mbedtls_ssl_session_reset( &context_ );
			if( result!=0 ) error.assign( result, mbedtls_error_category::instance() );
		}
		void sessionReset()
		{
			std::error_code error;
			sessionReset( error );
			if( error ) throw std::system_error( error );
		}

		void closeNotify( std::error_code& error )
		{
			int result;
			while( ( result=mbedtls_ssl_close_notify(&context_) ) != 0 )
			{
				if( result!=MBEDTLS_ERR_SSL_WANT_READ && result!=MBEDTLS_ERR_SSL_WANT_WRITE )
				{
					error.assign( result, mbedtls_error_category::instance() );
					return;
				}
			}
		}
		void closeNotify()
		{
			std::error_code error;
			closeNotify( error );
			if( error ) throw std::system_error( error );
		}

		std::string getCipherSuite() const
		{
			return mbedtls_ssl_get_ciphersuite( &context_ );
		}

		mbedtls_ssl_context* get(){return &context_;} // TODO - remove this once I have a more OO way to use the class
	protected:
		mbedtls_ssl_context context_;
		std::function<int(void*,const unsigned char*,size_t)> sendCallback_;
		std::function<int(void*,unsigned char*,size_t)> receiveCallback_;
		std::function<int(void*,unsigned char*,size_t,uint32_t)> receiveWithTimeoutCallback_;
	};

} // end of namespace mbedtlscpp

#endif // end of include guard
