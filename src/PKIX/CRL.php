<?php

/**
 * X.509 CRL creator
 *
 * @see https://www.ietf.org/rfc/rfc2459.txt
 */

namespace PKIX;

use DateTimeImmutable;
use \lyquidity\Asn1\Der\Decoder;
use \lyquidity\Asn1\Der\Encoder;
use \lyquidity\Asn1\Element;
use \lyquidity\Asn1\Element\BitString;
use \lyquidity\Asn1\Element\Enumerated;
use \lyquidity\Asn1\Element\GeneralizedTime;
use \lyquidity\Asn1\Element\Integer;
use \lyquidity\Asn1\Element\NullElement;
use \lyquidity\Asn1\Element\ObjectIdentifier;
use \lyquidity\Asn1\Element\OctetString;
use \lyquidity\Asn1\Element\Sequence;
use \lyquidity\Asn1\Element\UTCTime;
use \lyquidity\Asn1\Tag;
use \lyquidity\Asn1\UniversalTagID;
use \lyquidity\Ocsp\CertificateInfo;
use \lyquidity\Ocsp\CertificateLoader;

use function \lyquidity\Asn1\asInteger;
use function \lyquidity\Asn1\asOctetString;
use function \lyquidity\Asn1\asSequence;

/**
 * X.509 CRL
 */
class CRL
{
	/** @var array List of certificate revoke reasons */
	protected static $revoke_reasons = array(
		0 => 'unspecified',
		1 => 'keyCompromise',
		2 => 'CACompromise',
		3 => 'affiliationChanged',
		4 => 'superseded',
		5 => 'cessationOfOperation',
		6 => 'certificateHold',
		8 => 'removeFromCRL',
		9 => 'privilegeWithdrawn',
		10 => 'aACompromise'
	);
	/**
	 * Certificate revoke reasons: code -> name
	 *
	 * @param string $s name
	 * @return int code
	 */
	public static function getRevokeReasonCodeByName( $name ) 
	{
		$search_key = array_search($name, self::$revoke_reasons);
		if($search_key === false)
			return null;
		else
			return $search_key;
	}
	/**
	 * Certificate revoke reasons: name -> code
	 *
	 * @param int $c code
	 * @return string name
	 */
	public static function getRevokeReasonNameByCode( $code )
	{
		if( array_key_exists( $code, self::$revoke_reasons ) )
			return self::$revoke_reasons[ $code ];
		else
			return null;
	}
	
	
	/** @var array List of certificate hold instructions */
	protected static $hold_instructions = array(
		0 => 'None',
		1 => 'CallIssuer',
		2 => 'Reject'
	);

	/**
	 * Certificate hold instructions: code -> name
	 *
	 * @param string $s name
	 * @return null|int code
	 */
	public static function getHoldInstructionCodeByName( $name ) 
	{
		$search_key = array_search( $name, self::$hold_instructions );
		if($search_key === false)
			return null;
		else
			return $search_key;
	}

	/**
	 * Certificate hold instructions: name -> code
	 *
	 * @param int $c code
	 * @return string name
	 */
	public static function getHoldInstructionNameByCode( $name )  
	{
		if(array_key_exists( $name, self::$hold_instructions ) )
			return self::$hold_instructions[ $name ];
		else
			return null;
	}

	/** @var array List of bits of revoke reason (for CRL) */
	protected static $revoke_reason_bits = array(
		0 => null,
		1 => 'keyCompromise',
		2 => 'cACompromise',
		3 => 'affiliationChanged',
		4 => 'superseded',
		5 => 'cessationOfOperation',
		6 => 'certificateHold'
	);

	/**
	 * Get list of bits of revoke reason (for CRL)
	 *
	 * @return array
	 */
	public static function getRevokeReasonBits()
	{
		return self::$revoke_reason_bits;
	}

	//Internal undocumented function
	/**
	 * Return the value for an OID
	 *
	 * @param string $ext_oid
	 * @param \lyquidity\Asn1\Element\Sequence $extensions
	 * @return string
	 */
	private static function findExtensionValue( $ext_oid, $extensions ) 
	{
		if( preg_match( "|^\d+(\.\d+)+$|s", $ext_oid ) )
		{
			$is_oid = true;
		}
		else
		{
			$ext_name = $ext_oid;
			$ext_oid = \lyquidity\OID\OID::getOIDFromName($ext_name);
			$is_oid = ! is_null( $ext_oid );
		}

		foreach( $extensions->getElements() as $k => $seq ) 
		{
			if ( ! $seq->isConstructed() ) continue;
			/** @var \lyquidity\Asn1\Element\Sequence $seq */
			$oid = \lyquidity\Asn1\asObjectIdentifier( $seq->at(1) );
			if ( ! $oid ) continue;
			$EXT_OID = $oid->getIdentifier();
			if( $is_oid ? ( $EXT_OID == $ext_oid ) : ( \lyquidity\OID\OID::getNameFromOID( $EXT_OID ) == $ext_name ) )
			{
				$hasCritical = $seq->at(1) instanceof \lyquidity\Asn1\Element\Boolean;
				$extValue = \lyquidity\Asn1\asOctetString( $seq->at( $hasCritical ? 3 : 2 ) );
				return $extValue ? $extValue->getValue() : null;
			}
		}
		return null;
	}

	/**
	 * Get subject key identifier from decoded certificate data
	 *
	 * @param Sequence $cert_root root of decoded data
	 * @return Sequence
	 */
	public static function getExtVal_SubjectKeyIdentifier( $cert_root ) 
	{
		$ret = new Sequence();

		$is_v1 = false;
		if ( asSequence( $cert_root->first()->asSequence()->getFirstChildOfType( 0, Element::CLASS_CONTEXTSPECIFIC, Tag::ENVIRONMENT_EXPLICIT ) ) )
			$is_v1 = true;

		// Define subjKeyId
		$subjKeyId = null;
		$extensions = asSequence( $cert_root->first()->asSequence()->getFirstChildOfType( 3, Element::CLASS_CONTEXTSPECIFIC, Tag::ENVIRONMENT_EXPLICIT ) );

		if( $extensions )
		{
			$extval_subjKeyId = self::findExtensionValue('subjectKeyIdentifier', $extensions );
			if ( $extval_subjKeyId )
			{
				$subjKeyId = $extval_subjKeyId;
				// This my be an OctetString  If so,decode it.
				if ( ord( $subjKeyId[0] ) == UniversalTagID::OCTET_STRING )
				{
					$octet = asOctetString( (new Decoder())->decodeElement( $subjKeyId ) );
					$subjKeyId = $octet->getValue();
				}
			}
		}

		if ( $subjKeyId === null )
		{
			$certInfo = new \lyquidity\OCSP\CertificateInfo();
			$subjPubKey = $certInfo->extractSubjectPublicKeyBytes( $cert_root );
	
			if ( $subjPubKey )
				$subjKeyId = sha1( $subjPubKey, true );
		}

		// Write keyIdentifier
		// $ret->addElement(OctetString::create( $subjKeyId ) );
		// This is a way of setting the type id to zero which is required here
		$ret->addElement(
			OctetString::create( $subjKeyId )->setTag( Tag::implicit( 0 ) )
		);

		// Copy subject
		$subject = asSequence( $cert_root->first()->asSequence()->getNthChildOfType( $is_v1 ? 3 : 4, \lyquidity\Asn1\UniversalTagID::SEQUENCE ) );

		// Copy serial
		$serial = asInteger( $cert_root->first()->asSequence()->at( $is_v1 ? 1 : 2 ) )->getValue();

		// Write into authorityCertIssuer ([4] EXPLICIT Name)
		$ret->addElements( [
			// authorityCertIssuer
			Sequence::create( [ 
		 		OctetString::create( // Subject
					(new Encoder())->encodeElement( $subject )
				)->setTag( Tag::implicit( 4, Element::CLASS_CONTEXTSPECIFIC, true ) )
			] )->setTag( Tag::implicit( 1 ) )
			,
			// authorityCertSerialNumber
			Integer::create( $serial )->setTag( Tag::implicit( 2 ) )
		] );
		
		return $ret;
	}

	/**
	 * Generates and signs CRL from provided data
	 * Returns in DER format
	 *
	 * @param array $ci data for CRL creation. 
	 * Format: array(
	 *   'no' => number of CRL,
	 *   'version' => CRL format version, 1 or 2,
	 *   'days' => CRL validity in days from date of creation,
	 *   'alg' => OPENSSL_ALGO_*,
	 *   'revoked' => array( array( //list of revoked certificates
	 *     'serial' => S/N of revoked cert,
	 *     'rev_date' => date of revokation, timestamp,
	 *     'reason' => code of revokation reason, see self::getRevokeReasonCodeByName(),
	 *     'compr_date' => date when certifacate became compromised, timestamp,
	 *     'hold_instr' => code of hold instruction, see self::getHoldInstructionCodeByName(),
	 *   ), ... )
	 * )
	 * @param string $ca_pkey key pair for CA root certificate, got from openssl_pkey_get_private()
	 * @param string $ca_cert CA root certificate data in DER format
	 * @return [Sequence, string] A two element array of the CRL as a Sequence and in DER format
	 */
	static function create( $ci, $ca_pkey, $ca_cert ) 
	{
		$ca_decoded = (new CertificateLoader())->fromString( $ca_cert );

		//CRL version
		$crl_version = ( (isset( $ci['version'] ) && ( $ci['version'] == 2 || $ci['version'] == 1 ) ) ? $ci['version'] : 2 );

		//Algorithm
		$algs_cipher = array( OPENSSL_KEYTYPE_RSA, OPENSSL_KEYTYPE_DSA, OPENSSL_KEYTYPE_DH, OPENSSL_KEYTYPE_EC );
		$algs_hash = array( /*OPENSSL_ALGO_DSS1, */OPENSSL_ALGO_SHA1, OPENSSL_ALGO_MD5, OPENSSL_ALGO_MD4 );
		if ( defined('OPENSSL_ALGO_MD2') )
			$algs_hash[] = OPENSSL_ALGO_MD2;

		/** @var \OpenSSLAsymmetricKey $ca_pkey */
		$ca_pkey_details = openssl_pkey_get_details( $ca_pkey );

		if ( $ca_pkey_details === false )
			return false;

		$ca_pkey_type = $ca_pkey_details['type'];

		if ( ! in_array(  $ca_pkey_type, $algs_cipher ) )
			return false;

		if ( isset( $ci['alg']) && ! in_array( $ci['alg'], $algs_hash ) )
			return false;

		$crl_hash_alg = ( isset( $ci['alg'] ) ? $ci['alg'] : OPENSSL_ALGO_SHA1 );		

		$sign_alg_oid = \lyquidity\OID\OID::getAlgoOID($ca_pkey_type, $crl_hash_alg);

		if ( $sign_alg_oid === false )
			return false;

		//Create CRL structure
		$tbsCertList = new Sequence();

		if( $crl_version == 2  )
		{
			$tbsCertList->addElement( Integer::create( $crl_version - 1 ) );
		}

		$signatureAlg = Sequence::create([
			ObjectIdentifier::create( $sign_alg_oid ),
			NullElement::create()
		]);

		$thisUpdateTime = (new \DateTimeImmutable("now"))->setTimestamp($ci['update']);  // Makes sure the microseconds are zero
		$nextUpdateTime = $thisUpdateTime->add( new \DateInterval("P{$ci['days']}D") );

		$tbsCertList->addElements([
			$signatureAlg,
			( new CertificateInfo() )->extractIssuer( $ca_decoded ),
			UTCTime::create( $thisUpdateTime ),
			UTCTime::create( $nextUpdateTime )
		 ] );

		//Create CRL stricture
		$crl = Sequence::create([
			$tbsCertList
		]);
		
		//Revoked certs list
		if( isset( $ci['revoked']) && $ci['revoked'] && is_array( $ci['revoked'] ) )
		{
			$revokedCertificates = new Sequence();
			$tbsCertList->addElement( $revokedCertificates );

			foreach( $ci['revoked'] as $i => $revokedCert ) 
			{
				$revCert = Sequence::create( [ Integer::create( \gmp_import( $revokedCert['serial'] ) ) ] );
				$revokedCertificates->addElement( $revCert );

				if( ! is_null( $revokedCert['rev_date'] ) )
				{
					$revCert->addElement( UTCTime::create( (new DateTimeImmutable())->setTimestamp( $revokedCert['rev_date'] ) ) );
				}
				
				// Revoke Extensions
				if( $crl_version == 2 && ! is_null( $revokedCert['reason'] ) )
				{
					$crlExts = new Sequence();
					$revCert->addElement( $crlExts );

					$reasonCode = Sequence::create([
						ObjectIdentifier::create( \lyquidity\OID\OID::getOIDFromName("cRLReason") ),
						OctetString::create( (new Encoder())->encodeElement( Enumerated::create( $revokedCert['reason'] ) ) )
					] );

					$crlExts->addElement( $reasonCode );

					if( $revokedCert['reason'] == self::getRevokeReasonCodeByName('keyCompromise') && ! is_null( $revokedCert['compr_date'] ) )
					{
						// $crlExts->content['invalidityDate'] = new ASN1_SEQUENCE;
						$invalidityDate = Sequence::create( [
							ObjectIdentifier::create( \lyquidity\OID\OID::getOIDFromName("invalidityDate") ),
							OctetString::create( 
								(new Encoder())->encodeElement(
									GeneralizedTime::create( (new \DateTimeImmutable())->setTimestamp( $revokedCert['compr_date'] ) )
								)
							)
						] );
						$crlExts->addElement( $invalidityDate );
					}

					if( $revokedCert['reason'] == self::getRevokeReasonCodeByName('certificateHold') && ! is_null( $revokedCert['hold_instr'] ) )
					{
						// $crlExts->content['holdInstructionCode'] = new ASN1_SEQUENCE;
						$holdInstructionCode = Sequence::create( [
							ObjectIdentifier::create( \lyquidity\OID\OID::getOIDFromName("instructionCode") ),
							OctetString::create(
								(new Encoder())->encodeElement(
									ObjectIdentifier::create( \lyquidity\OID\OID::getOIDFromName( self::getHoldInstructionNameByCode( $revokedCert['hold_instr'] ) ) )
								)
							)
						] );

						$crlExts->addElement( $holdInstructionCode );
					}
				}
			}
		}

		// CRL Extensions
		if ( $crl_version == 2 ) 
		{
			$crlExts = new Sequence();
			$tbsCertList->addElement( $crlExts );
			$crlExts->setTag( Tag::explicit( 0 ) );

			$subjectKeyIdentifier = self::getExtVal_SubjectKeyIdentifier( $ca_decoded );

			$authorityKeyIdentifier = Sequence::create([
				ObjectIdentifier::create( \lyquidity\OID\OID::getOIDFromName("authorityKeyIdentifier") ),
				OctetString::create( (new Encoder())->encodeElement( $subjectKeyIdentifier ) ),
			]);
			$crlExts->addElement( $authorityKeyIdentifier );
			
			// echo join( ',', unpack( 'C*', (new Encoder())->encodeElement( $crlExts ) ) );

			if ( isset( $ci['no'] ) && is_numeric( $ci['no'] ) )
			{
				$cRLNumber = Sequence::create( [
					ObjectIdentifier::create( \lyquidity\OID\OID::getOIDFromName("cRLNumber") ),
					OctetString::create( (new Encoder())->encodeElement( Integer::create( $ci['no'] ) ) )
				] );
				$crlExts->addElement( $cRLNumber );
			}
		}

		// Sign CRL info
		$crl_info = (new Encoder())->encodeElement( $tbsCertList );
		$crl_sig = "";
		$crl_sign_result = openssl_sign( $crl_info, $crl_sig, $ca_pkey, $crl_hash_alg );
		if( ! $crl_sign_result )
			return false;
		
		//Add sign to CRL structure
		$crl->addElements( [
			Sequence::create( [ 
				ObjectIdentifier::create( $sign_alg_oid ),
				NullElement::create()
			] ),
			BitString::create( $crl_sig, 0 )
		] );
		
		//Encode CRL content to DER format
		$crl_encoded = ( new Encoder() )->encodeElement( $crl );
		return [ $crl, $crl_encoded ];
	}
}

?>