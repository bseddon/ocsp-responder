<?php
/*
 * PHP MalformedRequestResponse - OCSP response generator for PHP
 */
namespace PKIX\OCSP;

/**
 * %OCSP malformedRequest response
 */
class MalformedRequestResponse extends ExceptionResponse
{
	protected $OCSPStatus = \Ocsp\ERR_MALFORMED_ASN1;
}
