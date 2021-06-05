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
	protected $OCSPStatus = \Ocsp\ERR_UNAUTHORIZED;
}
