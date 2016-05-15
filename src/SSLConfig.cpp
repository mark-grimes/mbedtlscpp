#include "mbedtlscpp/SSLConfig.h"

#include "mbedtlscpp/X509Crt.h"
#include "mbedtlscpp/PKContext.h"
#include "mbedtlscpp/CtrDRBGContext.h"
#include "mbedtlscpp/mbedtls_error_category.h"

mbedtlscpp::SSLConfig::SSLConfig()
{
	mbedtls_ssl_config_init( &context_ );
}

mbedtlscpp::SSLConfig::~SSLConfig()
{
	mbedtls_ssl_config_free( &context_ );
}

void mbedtlscpp::SSLConfig::defaults( Endpoint endpoint, Transport transport, Preset preset, std::error_code& error )
{
	int end, trans, pre;
	switch( endpoint )
	{
		case Endpoint::CLIENT : end=MBEDTLS_SSL_IS_CLIENT; break;
		case Endpoint::SERVER : end=MBEDTLS_SSL_IS_SERVER; break;
	}
	switch( transport )
	{
		case Transport::STREAM : trans=MBEDTLS_SSL_TRANSPORT_STREAM; break;
		case Transport::DATAGRAM : trans=MBEDTLS_SSL_TRANSPORT_DATAGRAM; break;
	}
	switch( preset )
	{
		case Preset::DEFAULT : pre=MBEDTLS_SSL_PRESET_DEFAULT; break;
		default :
			throw std::runtime_error( "mbedtlscpp::SSLConfig::defaults not coded that Preset value yet" );
	}

	int result=mbedtls_ssl_config_defaults( &context_, end, trans, pre );
	if( result!=0 ) error.assign( result, mbedtls_error_category::instance() );
}

void mbedtlscpp::SSLConfig::defaults( Endpoint endpoint, Transport transport, Preset preset )
{
	std::error_code error;
	defaults( endpoint, transport, preset, error );
	if( error ) throw std::system_error( error );
}

void mbedtlscpp::SSLConfig::caChain( mbedtlscpp::X509Crt& certificateChain, mbedtls_x509_crl* pRevocationList )
{
	mbedtls_ssl_conf_ca_chain( &context_, &certificateChain.context_, pRevocationList );
}

void mbedtlscpp::SSLConfig::ownCert( mbedtlscpp::X509Crt& ownCertificate, mbedtlscpp::PKContext& privateKey, std::error_code& error )
{
	int result=mbedtls_ssl_conf_own_cert( &context_, &ownCertificate.context_, &privateKey.context_ );
	if( result!=0 ) error.assign( result, mbedtls_error_category::instance() );
}

void mbedtlscpp::SSLConfig::ownCert( mbedtlscpp::X509Crt& ownCertificate, mbedtlscpp::PKContext& privateKey )
{
	std::error_code error;
	ownCert( ownCertificate, privateKey, error );
	if( error ) throw std::system_error( error );
}

void mbedtlscpp::SSLConfig::authMode( AuthMode authMode )
{
	int mode;
	switch( authMode )
	{
	case AuthMode::VERIFY_NONE : mode=MBEDTLS_SSL_VERIFY_NONE; break;
	case AuthMode::VERIFY_OPTIONAL : mode=MBEDTLS_SSL_VERIFY_OPTIONAL; break;
	case AuthMode::VERIFY_REQUIRED : mode=MBEDTLS_SSL_VERIFY_REQUIRED; break;
	}
	mbedtls_ssl_conf_authmode( &context_, mode );
}

void mbedtlscpp::SSLConfig::rng( std::function<int(void*,unsigned char*,size_t)> generator, void* parameter )
{
	randomNumberGenerator_=generator;
	mbedtls_ssl_conf_rng( &context_, *randomNumberGenerator_.target<int(*)(void*,unsigned char*,size_t)>(), parameter );
}

void mbedtlscpp::SSLConfig::rngEasyDefault( CtrDRBGContext& ctrDrbgContext )
{
	rng( mbedtls_ctr_drbg_random, &ctrDrbgContext.context_ );
}

void mbedtlscpp::SSLConfig::dbg( std::function<void(void*,int,const char*,int,const char*)> debugCallback, void* parameter )
{
	debugCallback_=debugCallback;
	mbedtls_ssl_conf_dbg( &context_, *debugCallback_.target<void(*)(void*,int,const char*,int,const char*)>(), parameter );
}
