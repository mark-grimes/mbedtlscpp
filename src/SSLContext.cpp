#include "mbedtlscpp/SSLContext.h"

#include "mbedtlscpp/mbedtls_error_category.h"
#include "mbedtlscpp/SSLConfig.h"
#include "mbedtlscpp/NetContext.h"

mbedtlscpp::SSLContext::SSLContext()
{
	mbedtls_ssl_init(&context_);
}

mbedtlscpp::SSLContext::~SSLContext()
{
	mbedtls_ssl_free(&context_);
}

void mbedtlscpp::SSLContext::setup( const mbedtlscpp::SSLConfig& config, std::error_code& error )
{
	int result=mbedtls_ssl_setup( &context_, &config.context_ );
	if( result!=0 ) error.assign( result, mbedtls_error_category::instance() );
}

void mbedtlscpp::SSLContext::setup( const mbedtlscpp::SSLConfig& config )
{
	std::error_code error;
	setup( config, error );
	if( error ) throw std::system_error( error );
}

void mbedtlscpp::SSLContext::setHostname( const std::string& hostname, std::error_code& error )
{
	int result=mbedtls_ssl_set_hostname( &context_, hostname.c_str() );
	if( result!=0 ) error.assign( result, mbedtls_error_category::instance() );
}

void mbedtlscpp::SSLContext::setHostname( const std::string& hostname )
{
	std::error_code error;
	setHostname( hostname, error );
	if( error ) throw std::system_error( error );
}

void mbedtlscpp::SSLContext::handshake( std::error_code& error )
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

void mbedtlscpp::SSLContext::handshake()
{
	std::error_code error;
	handshake( error );
	if( error ) throw std::system_error( error );
}

int mbedtlscpp::SSLContext::getVerifyResult()
{
	return mbedtls_ssl_get_verify_result( &context_ );
}

void mbedtlscpp::SSLContext::setBIO( void* parameter,
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

void mbedtlscpp::SSLContext::setBIOEasyDefault( mbedtlscpp::NetContext& net )
{
	setBIO( &net.context_, mbedtls_net_send, mbedtls_net_recv, nullptr );
}

size_t mbedtlscpp::SSLContext::write( const unsigned char* pBuffer, size_t length, std::error_code& error )
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

size_t mbedtlscpp::SSLContext::write( const unsigned char* pBuffer, size_t length )
{
	std::error_code error;
	size_t bytesWritten=write( pBuffer, length, error );
	if( error ) throw std::system_error( error );
	return bytesWritten;
}

void mbedtlscpp::SSLContext::writeAll( const unsigned char* pBuffer, size_t length, std::error_code& error )
{
	while( length>0 )
	{
		size_t bytesWritten=write( pBuffer, length, error );
		if( error ) return;
		pBuffer+=bytesWritten;
		length-=bytesWritten;
	}
}

void mbedtlscpp::SSLContext::writeAll( const unsigned char* pBuffer, size_t length )
{
	std::error_code error;
	writeAll( pBuffer, length, error );
	if( error ) throw std::system_error( error );
}

size_t mbedtlscpp::SSLContext::read( unsigned char* pBuffer, size_t length, std::error_code& error )
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

size_t mbedtlscpp::SSLContext::read( unsigned char* pBuffer, size_t length )
{
	std::error_code error;
	size_t bytesRead=read( pBuffer, length, error );
	if( error ) throw std::system_error( error );
	return bytesRead;
}

void mbedtlscpp::SSLContext::sessionReset( std::error_code& error )
{
	int result=mbedtls_ssl_session_reset( &context_ );
	if( result!=0 ) error.assign( result, mbedtls_error_category::instance() );
}

void mbedtlscpp::SSLContext::sessionReset()
{
	std::error_code error;
	sessionReset( error );
	if( error ) throw std::system_error( error );
}

void mbedtlscpp::SSLContext::closeNotify( std::error_code& error )
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

void mbedtlscpp::SSLContext::closeNotify()
{
	std::error_code error;
	closeNotify( error );
	if( error ) throw std::system_error( error );
}

std::string mbedtlscpp::SSLContext::getCipherSuite() const
{
	return mbedtls_ssl_get_ciphersuite( &context_ );
}
