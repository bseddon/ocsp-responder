<?php

use PKIX\OCSP\StoreCA;

error_reporting(E_ALL);

if ( ! class_exists('\\lyquidity\\OCSP\\Ocsp') ) // Will not be loaded if Composer autoload is being used
	require_once( __DIR__ . '/../../requester/src/autoload.php');
if ( ! class_exists('\\PKIX\\OCSP\\Request') ) // Will not be loaded if Composer autoload is being used
	require_once( __DIR__ . '/autoload.php');

try 
{
	// Set constant variables
	// $caConfigFile = dirname( get_included_files()[0] ) . '/certification/ca.conf';
	$caConfigFile = dirname( end(debug_backtrace())['file'] ) . '/certification/ca.conf';

	$caFolder = StoreCA::getCAFolder( $caConfigFile );
	$caKey = $caFolder . '/ca.key';
	$caCert = $caFolder . '/ca.crt';

	// Load the CA certificate
	$certificateLoader = new \lyquidity\OCSP\CertificateLoader();
	$caCertificate = file_get_contents( $caCert ); // PEM
	$caSequence = $certificateLoader->fromString( $caCertificate );
	$certificateInfo = new lyquidity\OCSP\CertificateInfo();
	// This requestInfo is NOT the information from the caller. Information from the caller has not been retrieved yet.
	// It is used to build a list of valid issuer certificates.
	$requestInfo = $certificateInfo->extractRequestInfo( $caSequence, $caSequence );
	$issuerCertificates[ base64_encode( sha1( $requestInfo->getIssuerPublicKeyBytes(), true) ) ] = array( $requestInfo, file_get_contents( $caKey ), $caSequence  );

	// Load the request
	$reqData = \PKIX\OCSP\Request::receive(array('GET', 'POST'));
	$req = new \PKIX\OCSP\Request($reqData);
	$certID = $req->getCertID();

	// Use the file store (select a different one as needed)
	$store = new \PKIX\OCSP\StoreCA( array( 'configFile' => $caConfigFile ) );

	// Create the response DER stream
	$respData = $store->getResp( $certID, $issuerCertificates );

	// Create an object so the final OCSP response can be returned with the appropriate headers
	$resp = new \PKIX\OCSP\Response($respData);
	$resp->setMaxAge(300);
	// $cs = $resp->getCertStatus();
	// error_log("certStatus:". var_export($cs, true));
	$resp->respond();
}
catch ( \PKIX\Exception\Exception $e )
{
	logException($e);

	switch( $e->getCode() )
	{
		case \lyquidity\OCSP\Ocsp::ERR_MALFORMED_ASN1:
		case \lyquidity\OCSP\Ocsp::ERR_INTERNAL_ERROR:
		case \lyquidity\OCSP\Ocsp::ERR_TRY_LATER:
		case \lyquidity\OCSP\Ocsp::ERR_SIG_REQUIRED:
		case \lyquidity\OCSP\Ocsp::ERR_UNAUTHORIZED:
			$r = \PKIX\OCSP\ExceptionResponse::createErrorResponse($e->getCode());
			break;

		case \lyquidity\OCSP\Ocsp::ERR_REQLIST_EMPTY:
			$r = \PKIX\OCSP\ExceptionResponse::createErrorResponse( \lyquidity\OCSP\Ocsp::ERR_MALFORMED_ASN1);
			break;

		case \lyquidity\OCSP\Ocsp::ERR_SUCCESS:
			error_log("Caught exception $e with status code " . $e->getCode()
				. "which should not happen! Check the code at "
				. $e->getFile() . ":" . $e->getLine());
		/* no break here - falling back to Internal Server Error */
		default:
			$r = new \PKIX\OCSP\InternalErrorResponse();
			break;
	}

	/* DBG */
	error_log("sending " . get_class($r));
	$r->respond();

}
catch( \PKIX\Exception\HTTPException $e )
{
	logException($e);

	$c = $e->getCode();
	if ($c < 100 || $c > 599) {
		error_log(get_class($e) . " called with non HTTP error code $c! "
			. "Check the code at " . $e->getFile() . ":" . $e->getLine());
		$c = \PKIX\Message::HTTP_INTERNAL_SERVER_ERROR;
	}
	sendHTTPError($c);
}
catch( \PKIX\Exception\Exception $e )
{
	logException($e);

	switch( $e->getCode() )
	{
		case \PKIX\OCSP\ERR_CONFIG_ERROR:
			$r = new \PKIX\OCSP\InternalErrorResponse();
			break;
		case \PKIX\OCSP\ERR_NOT_FOUND:
			$r = new \PKIX\OCSP\UnauthorizedResponse();
			break;
		default:
			error_log(get_class($e) . " caught with unexpected code " . $e->getCode() . "! "
				. "Check the code at " . $e->getFile() . ":" . $e->getLine());
			$r = new \PKIX\OCSP\InternalErrorResponse ();
			break;
	}

	$r->respond();

}
catch( \Exception $e)
{
	error_log("Oops! Caught by unexpected exception "
		. get_class($e) . ":[" . $e->getCode() . "] "
		. $e->getMessage() . " at " . $e->getFile() . ":" . $e->getLine() . "\n");
	$r = new \PKIX\OCSP\InternalErrorResponse();
	$r->respond();
}

/* utils */
function sendHTTPError($status)
{
	//  header($e->getMessage(), 1, $e->getCode());
	header($_SERVER['SERVER_PROTOCOL'] . " $status");
}

function logException($e)
{
	error_log("Caught " . get_class($e) . ":[" . $e->getCode() . "] "
		. $e->getMessage() . " at " . $e->getFile() . ":" . $e->getLine());
}
