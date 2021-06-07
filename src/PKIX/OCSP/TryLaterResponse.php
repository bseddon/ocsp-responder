<?php
/*
 * PHP TryLaterResponse - OCSP response generator for PHP
 */
namespace PKIX\OCSP;

/**
 * %OCSP tryLater response
 */
class TryLaterResponse extends ExceptionResponse
{
	protected $OCSPStatus = \Ocsp\Ocsp::ERR_TRY_LATER;
}
