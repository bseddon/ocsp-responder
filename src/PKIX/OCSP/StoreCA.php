<?php

/**
 * This concrete implementation of the abstract class Store provides a means to access a CA repository that is 
 * based on a database file created and maintained by the OpenSSL 'ca' functions. See the readme file for an
 * an example of using OpenSSL to create a CA, generate and revoke certificates.
 * 
 * It's expected that the CA files will exist in a folder that is not accessible from the internet.
 */

namespace PKIX\OCSP;

use Ocsp\Asn1\Element\Enumerated;
use Ocsp\Asn1\Element\GeneralizedTime;
use Ocsp\Asn1\Element\Sequence;
use Ocsp\Asn1\Element\UTCTime;
use Ocsp\Asn1\Tag;
use PKIX\CRL;
use PKIX\Exception\Exception;

use const Ocsp\ERR_UNAUTHORIZED;

/**
 * File system-based implementation of %OCSP responses storage.
 */
class StoreCA extends Store 
{
	/**
	 * Names of columns in an OpenSSL CA database file
	 */
	public const keys = array(
		'status' => 0,
		'expiryDate' => 1,
		'revokedDate' => 2,
		'serialNumber' => 3,
		'filename' => 4,
		'distinguishedName' => 5
	);

	/**
	 * Create an indexed array of a CA database created by OpenSSL
	 *
	 * @param string[] $keys
	 * @return string[]
	 */
	public static function getIndexIssuedCertificatesInfo( $keys, $certificateDatabase )
	{	
		$fp = fopen( $certificateDatabase, 'r' );
		if ( $fp === false )
		{
			throw new \Exception("Unable to access the certificate database file: $certificateDatabase");
		}

		$keysCount = count( $keys );
		$result = array();

		try
		{
			while ( ! feof( $fp ) )
			{
				$line = fgets( $fp, 2048);
				if ( ! $line ) continue;
	
				$data = str_getcsv( $line, "\t" );
				if ( count( $data ) != $keysCount )
				{
					throw new \Exception("A database row does not have the required fields: " . join( ',', $data ) );
				}
	
				$result[ $data[ $keys['serialNumber'] ] ] = array_reduce( array_keys( $keys ), function( $carry, $key ) use( $data, $keys ) { $carry[ $key ] = $data[ $keys[ $key ] ]; return $carry; }, [] );
			}                              
	
			return $result;
		}
		catch( \Exception $ex )
		{
			throw $ex;
		}
		finally
		{
			fclose( $fp );
		}
	}

	public static function getCAFolder( $configPath )
	{
		$base = dirname( $configPath );
		$conf = parse_ini_file( $configPath );
		$dir = $conf['dir'] ?? false;

		if ( ! $dir || ! $dir = realpath( "$base/$dir" ) )
		{
			throw new \Exception('The folder does not exist: '  . $dir );
		}

		return $dir;
	}

	public static function getCADatabase( $configPath )
	{
		$base = dirname( $configPath );
		$conf = parse_ini_file( $configPath );
		if ( ! $database = $conf['database'] ) return;
	
		$conf = array_reduce( array_keys( $conf ), function( $carry, $key ) use( &$conf )
		{
			$value =  $conf[ $key ];
			if ( ! $key = trim( explode( '#', $key )[0] ) ) return $carry;
			$value = trim( explode( '#', $value )[0] );
			$carry[ '/\$' . $key . '/' ] = $value;
			return $carry;
		}, [] );
		$db = preg_replace( array_keys( $conf ), array_values( $conf ), $database );
		if ( $db[0] == '.' )
		{
			if ( ! $db = realpath( "$base/$db" ) )
			{
				throw new \Exception('The file does not exist: '  . $db );
			}
		}

		return $db;
	}

	/**
	 * An array containing arrays of strings that hold CA database information
	 * @var stting[][]
	 */
	protected $certificateInfo = array();

	/**
	 * Configure the storage.
	 *
	 * @param string[] $params Array containing the configiration
	 * directives:
	 * - configFile - full path do the storage root directory
	 *
	 * @throws \PKIX\Exception\Exception with value ERR_CONFIG_ERROR
	 */
	public function config( $params )
	{
		if ( isset( $params['configFile'] ) )
		{
			$this->setConfigFile( $params['configFile'] );
		}
	}

	/**
	 * Set the storage root directory
	 *
	 * @param string $basedir full path to the storage root directory
	 *
	 * @throws \PKIX\Exception\Exception with value ERR_CONFIG_ERROR
	 */
	public function setConfigFile( $configFile )
	{
		if ( file_exists( $configFile ) )
		{
			$this->configFile = $configFile;
			$db = self::getCADatabase( $configFile ); 
			$this->certificateInfo = self::getIndexIssuedCertificatesInfo( self::keys, $db );
		}
		else
		{
			throw new Exception( "Directory $configFile does not exists", ERR_CONFIG_ERROR );
		}
	}

	/**
	 * Get the response to be generated for the requested certificate
	 *
	 * @param string[] $cid A list of certificate parameters generated by the requestor
	 * @param Sequence[] $certificates An array of the CAs certificate ids indexed by public key hash
	 * @return string Base 64 encoded DER representation of the response
	 */
	public function getResp( $cid, $certificates )
	{
		// Find the certificate
		if ( ! isset( $certificates[ base64_encode( $cid['issuerKeyHash'] ) ] ) )
		{
			throw new Exception( "Issuer certificate not found", ERR_UNAUTHORIZED );
		}

		/** 
		 * @var Sequence $certificate
		 * @var string $privateKey
		 */
		list( $requestInfo, $privateKey, $caSequence ) = $certificates[ base64_encode( $cid['issuerKeyHash'] ) ];

		// $info = new CertificateInfo();
		// $requestInfo = $info->extractRequestInfo( $caSequence, $caSequence );
		if ( ! $publicKeyBytes = $requestInfo->getIssuerPublicKeyBytes() ?? null )
		{
			throw new Exception( "Unable to find the public key in the responder certificate", ERR_UNAUTHORIZED );
		}

		// Access the serial number
		$serialNumber = strtoupper( bin2hex( $cid['serialNumber'] ) );
		$certInfo = $this->certificateInfo[ $serialNumber ];

		$expiryDate = UTCTime::decodeUTCTime( $certInfo['expiryDate'] );
		if ( time() > $expiryDate->getTimestamp() )
		{
			$certInfo['status'] = 'E';
		}

		$status = 0;
		$revokedInfo = null;
		switch( $certInfo['status'] )
		{
			case 'E': // expired
				throw new Exception( "Certificate revoked", ERR_UNAUTHORIZED );
			case 'R': // revoked
				$status = 1;
				list( $date, $reason ) = explode( ',', $certInfo['revokedDate'] );
				// The CRL date is UTC but the RevokeInfo date is GeneralizedTime
				$utcDateTime = UTCTime::decodeUTCTime( $date );

				$revokedInfo = Sequence::create( [
					GeneralizedTime::create( $utcDateTime ),
					Enumerated::create( CRL::getRevokeReasonCodeByName( $reason ) )->setTag( Tag::explicit( 0 ) )
				] );
		}

		return $this->createResponse( $cid, $status, $publicKeyBytes, $privateKey, $caSequence, $revokedInfo );
	}

	/**
	 * Get the path to the response from the CertID $cid
	 *
	 * @param array $cid CertID
	 * @return string the constructed path
	 */
	private function getPath( $cid ) 
	{
		return $this->_basedir . "/" . 
			hash('sha256', 
				implode("/",
					array(
						$cid['hashAlgorithm'],
						$cid['issuerNameHash'],
						$cid['issuerKeyHash'],
						$cid['serialNumber']
					)
				)
			);
	}
}
