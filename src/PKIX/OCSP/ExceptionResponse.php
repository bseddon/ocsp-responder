<?php
/*
 * PHP ExceptionResponse - OCSP response generator for PHP
 */
namespace PKIX\OCSP;

/**
 * Generic %OCSP error response.  As the response messages are not signed, 
 * the signature verification related functions are not implemented.
 */
class ExceptionResponse extends Response
{
	protected $OCSPStatus = \Ocsp\ERR_SUCCESS;
	protected $HTTPStatus = self::HTTP_OK;

	/**
	 * The init() function is no-op for error responses.
	 *
	 * @param mixed $data Ignored
	 */
	protected function init( $data )
	{
	}

	/** @name HTTP interface (local overrides) */
	/**@{*/
    public function respondHeaders()
	{
		return array('Content-Type' => static::mimeType);
	}

    /* public function HTTPStatusHeader () { */
    /*   if (isset($this->HTTPStatus)) { */
    /* 	return $_SERVER['SERVER_PROTOCOL'].' '.$this->HTTPStatus; */
    /*   } */
    /* } */

    /**@} end of HTTP interface */

    /**
	 * Factory method for creating specific %OCSP error responses.
	 *
	 * @param int $errcode %OCSP error code, one of:
	 * - ERR_MALFORMED_ASN1 (1) (called malformedRequest in RFC2560)
	 * - ERR_INTERNAL_ERROR (2)
	 * - ERR_TRY_LATER (3)
	 * - ERR_SIG_REQUIRED (5)
	 * - ERR_UNAUTHORIZED (6)
	 *
	 * @return ExceptionResponse subclass
	 */
    public static function createErrorResponse($errcode)
	{
		switch ($errcode)
		{
			case \Ocsp\ERR_MALFORMED_ASN1:
				return new MalformedRequestResponse();
			case \Ocsp\ERR_INTERNAL_ERROR:
				return new InternalErrorResponse();
			case \Ocsp\ERR_TRY_LATER:
				return new TryLaterResponse();
			case \Ocsp\ERR_SIG_REQUIRED:
				return new SigRequiredResponse();
			case \Ocsp\ERR_UNAUTHORIZED:
				return new UnauthorizedResponse();

			default:
				return new static();
		}
	}

    /**
	 * Create ASN.1 %OCSP error response
	 */
    public function getData()
	{
		// This response should be the same as pack("C*", 0x30, 0x03, 0x0a, 0x01, $this->OCSPStatus);
		return( new \Ocsp\Asn1\Der\Encoder() )->encodeElement( 
			\Ocsp\Asn1\Element\Sequence::create([
				\Ocsp\Asn1\Element\Enumerated::create( $this->OCSPStatus )
			])
		);
	}
}
