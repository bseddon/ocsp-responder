<?php

/**
 * This concrete implementation of the abstract class Store provides a means to access a CA repository that is 
 * based on a database file created and maintained by the OpenSSL 'ca' functions. See the readme file for an
 * an example of using OpenSSL to create a CA, generate and revoke certificates.
 * 
 * It's expected that the CA files will exist in a folder that is not accessible from the internet.
 */

namespace PKIX\OCSP;

use \lyquidity\Asn1\Element\Enumerated;
use \lyquidity\Asn1\Element\GeneralizedTime;
use \lyquidity\Asn1\Element\Sequence;
use \lyquidity\Asn1\Element\UTCTime;
use \lyquidity\Asn1\Tag;
use PKIX\CRL;
use PKIX\Exception\Exception;
use PKIX\Exception\StoreException;

// Reason codes
define( 'KeyCompromise', 'keyCompromise' ); // A computer is stolen or a smart card is lost
define( 'CACompromise', 'CACompromise' ); // A CA certificate is compromised
define( 'AffiliationChanged', 'affiliationChanged' ); // An employee is terminated or suspended
define( 'Superseded', 'superseded' ); // If a smart card fails or the legal name of a user has changed
define( 'CessationOfOperation', 'cessationOfOperation' ); // An issued certificate is replaced
define( 'CertificateHold', 'certificateHold' ); // A certificate needs to be put on hold temporarily
define( 'RemoveFromCRL', 'removeFromCRL' ); // A CA is removed from the network
define( 'Unspecified', 'unspecified' ); // You revoke a certificate without providing a reason

// Fields
define( 'STATUS', 'status' );
define( 'CREATEDATE', 'createDate' );
define( 'EXPIRYDATE', 'expiryDate' );
define( 'REVOKEDDATE', 'revokedDate' );
define( 'SERIALNUMBER', 'serialNumber' );
define( 'FILENAME', 'filename' );
define( 'DISTINGUISHEDNAME', 'distinguishedName' );

/**
 * File system-based implementation of %OCSP responses storage.
 */
class StoreCA extends Store 
{
	/**
	 * Names of columns in an OpenSSL CA database file
	 */
	public const keys = array(
		STATUS => 0,
		EXPIRYDATE => 1,
		REVOKEDDATE => 2,
		SERIALNUMBER => 3,
		FILENAME => 4,
		DISTINGUISHEDNAME => 5,
		CREATEDATE => 6
	);

	/**
	 * Create an indexed array of a CA database created by OpenSSL
	 *
	 * @param string[] $keys
	 * @param string $certificateDatabase
	 * @return string[]
	 */
	public static function getIndexIssuedCertificatesInfo( $keys, $certificateDatabase )
	{	
		$fp = fopen( $certificateDatabase, 'r' );
		if ( $fp === false )
		{
			throw new StoreException("Unable to access the certificate database file: $certificateDatabase");
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
					throw new StoreException("A database row does not have the required fields: " . join( ',', $data ) );
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

	/**
	 * Add the certificate to the CA database.  The database file will be created 
	 *
	 * @param string $certificatePEM
	 * @param string $databaseFile
	 * @return void
	 * @throws \Exception
	 */
	public static function recordCertificate( $certificatePEM, $databaseFile )
	{
		/**
		 	status flag (V=valid, R=revoked, E=expired).
			expiration date in YYMMDDHHMMSSZ format.
			revocation date in YYMMDDHHMMSSZ[,reason] format. Empty if not revoked.
			serial number in hex.
			filename or literal string ‘unknown’.
			distinguished name.
		 */

		$database = "";
		if ( file_exists( $databaseFile ) )
		{
			$database = file_get_contents( $databaseFile );
		}

		if ( $database && substr( $database, -1 ) != "\n" )
		{
			$database .= "\r\n";
		}

		$data = openssl_x509_parse( $certificatePEM );
		if ( ! $data ) 
		{
			throw new \Exception( __("The certificate PEM cannot be parsed", 'ca') );
		}

		if ( strpos( $database, $data['serialNumberHex'] ) !== false )
		{
			throw new \Exception( __( "The certificate with serial '{$data['serialNumberHex']}' number has already been used", 'ca' ) );
		}

		$parts = array(
			STATUS => "V",
			EXPIRYDATE => $data['validTo'],
			REVOKEDDATE => "",
			SERIALNUMBER => $data['serialNumberHex'],
			FILENAME => "unknown",
			DISTINGUISHEDNAME => $data['name'],
			CREATEDATE => date('ymdHis') . 'Z'
		);

		$database .= join( "\t", $parts );

		file_put_contents( $databaseFile, $database );
	}

	/**
	 * Revoke all and save the database
	 *
	 * @param string $certificateDatabase
	 * @return void
	 */
	public static function revokeAllCertificates( $certificateDatabase, $reason = KeyCompromise )
	{
		$records = array_map( function( $record ) use( $reason )
		{
			$record[STATUS] = 'R';
			$record[REVOKEDDATE] = date('ymdHis') . 'Z,' . $reason;
			return $record;
		},  StoreCA::getIndexIssuedCertificatesInfo( StoreCA::keys, $certificateDatabase ) );

		self::saveRecords( $records, $certificateDatabase );
	}

	/**
	 * Revoke a specific certificate identified by serial number and save the database
	 * @param string $serialNumber
	 * @param string $certificateDatabase
	 * @return void
	 */
	public static function revokeCertificate( $serialNumber, $certificateDatabase, $reason = KeyCompromise )
	{
		$records = StoreCA::getIndexIssuedCertificatesInfo( StoreCA::keys, $certificateDatabase );
		if ( ! isset( $records[ $serialNumber ] ) )
			throw new \Exception( __('The serial number does not exist in the CA database', 'ca' ) );
		$records[ $serialNumber ][STATUS] = 'R';
		$records[ $serialNumber ][REVOKEDDATE] = date('ymdHis') . 'Z,' . $reason;

		self::saveRecords( $records, $certificateDatabase );
	}

	/**
	 * Revoke a specific certificate identified by serial number and save the database
	 * @param string $serialNumber
	 * @param string $certificateDatabase
	 * @return void
	 */
	public static function restoreCertificate( $serialNumber, $certificateDatabase )
	{
		$records = StoreCA::getIndexIssuedCertificatesInfo( StoreCA::keys, $certificateDatabase );
		if ( ! isset( $records[ $serialNumber ] ) )
			throw new \Exception( __('The serial number does not exist in the CA database', 'ca' ) );
		$records[ $serialNumber ][STATUS] = 'V';
		$records[ $serialNumber ][REVOKEDDATE] = '';

		self::saveRecords( $records, $certificateDatabase );
	}

	/**
	 * Revoke all and save the database
	 * @param string[][] $records
	 * @param string $certificateDatabase
	 * @return void
	 */
	public static function saveRecords( $records, $certificateDatabase )
	{
		$database = join( "\r\n", array_map( function( $record ) 
		{
			return join("\t", $record );
		}, $records ) );

		if ( file_put_contents( $certificateDatabase, $database ) === false )
		{
			throw new \Exception( __("Unable to saved the changed CA database", 'ca' ) );
		}
	}

	public static function getCAFolder( $configPath )
	{
		$base = dirname( $configPath );
		$conf = str_replace( "#", ";", file_get_contents( $configPath ) );
		$conf = parse_ini_string( $conf );
		$dir = $conf['dir'] ?? false;

		if ( ! $dir || ! $dir = realpath( "$base/$dir" ) )
		{
			throw new StoreException('The folder does not exist: '  . $dir );
		}

		return $dir;
	}

	/**
	 * Retrieve the path to the CA database file
	 * @param string $configPath
	 * @return string
	 */
	public static function getCADatabase( $configPath )
	{
		return self::getCAField( $configPath, 'database' );
	}

	/**
	 * Retrieve the path to the CA certificate
	 * @param string $configPath
	 * @return string
	 */
	public static function getCACertificatePath( $configPath )
	{
		return self::getCAField( $configPath, 'certificate' );
	}

	/**
	 * Retrieve the bytes of the CA certificate
	 * @param string $configPath
	 * @return string[]|false A byte array or false if the file does not exist
	 */
	public static function getCACertificateBytes( $configPath )
	{
		$path = self::getCACertificatePath( $configPath );
		return self::getFileContents( $path );
	}

	/**
	 * Retrieve the path to the CA private key
	 * @param string $configPath
	 * @return string
	 */
	public static function getCAPrivatePath( $configPath )
	{
		return self::getCAField( $configPath, 'private_key' );
	}

	/**
	 * Retrieve the bytes of the CA certificate
	 * @param string $configPath
	 * @return string[]|false A byte array or false if the file does not exist
	 */
	public static function getCAPrivateBytes( $configPath )
	{
		$path = self::getCAPrivatePath( $configPath );
		return self::getFileContents( $path );
	}

	/**
	 * Get the file contents if the path is valid or return false
	 * @param string $path
	 * @return string|false
	 */
	private static function getFileContents( $path )
	{
		if ( ! file_exists( $path ) ) return false;
		return file_get_contents( $path );
	}

	/**
	 * Core function to retrive a CA value
	 * @param string $configPath
	 * @param string $fieldName
	 * @return string
	 */
	private static function getCAField( $configPath, $fieldName )
	{
		$base = dirname( $configPath );
		$ini = str_replace( "#", ";", file_get_contents( $configPath ) );
		$conf = parse_ini_string( $ini );
		if ( ! $fieldValue = $conf[ $fieldName ] ) return;
	
		$conf = array_reduce( array_keys( $conf ), function( $carry, $key ) use( &$conf )
		{
			$value =  $conf[ $key ];
			if ( ! $key = trim( explode( '#', $key )[0] ) ) return $carry;
			$value = trim( explode( '#', $value )[0] );
			$carry[ '/\$' . $key . '/' ] = $value;
			return $carry;
		}, [] );

		$result = preg_replace( array_keys( $conf ), array_values( $conf ), $fieldValue );

		if ( $result[0] == '.' )
		{
			if ( ! $result = realpath( "$base/$result" ) )
			{
				throw new \Exception('The file does not exist: '  . $result );
			}
		}

		return $result;
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
	 * @param Sequence[] $issuerCertificates An array of the CAs certificate ids indexed by public key hash
	 * @return string Base 64 encoded DER representation of the response
	 */
	public function getResp( $cid, $issuerCertificates )
	{
		// Find the certificate
		if ( ! isset( $issuerCertificates[ base64_encode( $cid['issuerKeyHash'] ) ] ) )
		{
			throw new Exception( "Issuer certificate not found", \lyquidity\OCSP\Ocsp::ERR_UNAUTHORIZED );
		}

		/** 
		 * @var Sequence $certificate
		 * @var string $privateKey
		 */
		list( $requestInfo, $privateKey, $caSequence ) = $issuerCertificates[ base64_encode( $cid['issuerKeyHash'] ) ];

		// $info = new CertificateInfo();
		// $requestInfo = $info->extractRequestInfo( $caSequence, $caSequence );
		if ( ! $publicKeyBytes = $requestInfo->getIssuerPublicKeyBytes() ?? null )
		{
			throw new Exception( "Unable to find the public key in the responder certificate", \lyquidity\OCSP\Ocsp::ERR_UNAUTHORIZED );
		}

		// Access the serial number of the caller's certificate. Its part of the request.
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
				throw new Exception( "Certificate revoked", \lyquidity\OCSP\Ocsp::ERR_UNAUTHORIZED );
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
	 * Create a CRL for the CA
	 * @return string
	 */
	public function createCRL()
	{
		$ca_cert = self::getCACertificateBytes( $this->configFile );
		$ca_keyBytes  = self::getCAPrivateBytes( $this->configFile );

		$revoked = array_reduce( $this->certificateInfo, function( $carry, $certificate )
		{
			if ( $certificate['status'] == 'R' )
			{
				@list( $revokedDate, $reason ) = explode(',', $certificate['revokedDate'] );
				$revDate = \lyquidity\Asn1\Element\UTCTime::decodeUTCTime( $revokedDate );
				$carry[] = array(
					'serial' => hex2bin( $certificate['serialNumber'] ),
					'rev_date' => $revDate->getTimestamp(),
					'reason' => $reason ? \PKIX\CRL::getRevokeReasonCodeByName( $reason ) : '',
					'compr_date' => $revDate->sub( new \DateInterval('P1D'))->getTimestamp(),
					'hold_instr' => null,
				);
			}
			return $carry;
		}, array() );
	
		/** @var \DateTimeImmutable $date */
		$date = new \DateTimeImmutable("now");
	
		//Create CRL
		$ci = array(
			'no' => 1,
			'version' => 2,
			'days' => 30,
			// 'days' => 1,
			'alg' => OPENSSL_ALGO_SHA1,
			'update' => $date->getTimestamp(),
			'next' => $date->add( new \DateInterval('P1D'))->getTimestamp(),
			'revoked' => $revoked
		);

		$ca_key = openssl_get_privatekey( $ca_keyBytes );

		list( $crl, $crl_data ) = \PKIX\CRL::create( $ci, $ca_key, $ca_cert );
		
		return $crl;
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
