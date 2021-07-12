<?php
/*
 * PHP UnauthorizedResponse - OCSP response generator for PHP
 */
namespace PKIX\OCSP;

/**
 * %OCSP unauthorized response
 */
class UnauthorizedResponse extends ExceptionResponse
{
	protected $OCSPStatus = \lyquidity\OCSP\Ocsp::ERR_UNAUTHORIZED;
}
