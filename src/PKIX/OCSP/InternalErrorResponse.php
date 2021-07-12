<?php
/*
 * PHP InternalErrorResponse - OCSP response generator for PHP
 */
namespace PKIX\OCSP;

/**
 * %OCSP internalError response
 */
class InternalErrorResponse extends ExceptionResponse
{
	protected $OCSPStatus = \lyquidity\OCSP\Ocsp::ERR_INTERNAL_ERROR;
}
