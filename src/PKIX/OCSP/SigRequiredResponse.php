<?php
/*
 * PHP SigRequiredResponse - OCSP response generator for PHP
 */
namespace PKIX\OCSP;

/**
 * %OCSP sigRequired response
 */
class SigRequiredResponse extends ExceptionResponse
{
	protected $OCSPStatus = \lyquidity\OCSP\Ocsp::ERR_INTERNAL_ERROR;
}
