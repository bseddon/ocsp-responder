<?php

function responder_autoload( $classname )
{
	$prefix = 'PKIX\\';
	if ( strpos( $classname, $prefix ) !== 0 ) return false;
	// $filename = substr( $classname, strlen( $prefix ) ) . '.php';
	$filename = "$classname.php";
	require_once  __DIR__ . "/$filename";
}

spl_autoload_register( 'responder_autoload' );
