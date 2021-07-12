<?php
/*
 * PHP SingleResponse - OCSP response for a specific certificate validation request
 */
namespace PKIX\OCSP;

use \lyquidity\Asn1\Element;
use \lyquidity\Asn1\Element\GeneralizedTime;
use \lyquidity\Asn1\Tag;
use \lyquidity\Asn1\UniversalTagID;
use \lyquidity\Asn1\Exception\Asn1DecodingException;
use \PKIX\CRL;
use \PKIX\Exception\ResponseException;

use function \lyquidity\Asn1\asRawConstructed;

/**
 * SingleResponse message (see RFC6960)
 */
class SingleResponse extends \PKIX\Message
{
	protected $CertID;
	protected $certStatus;
	protected $thisUpdate;
	protected $nextUpdate;

	/**
	 * Constructor
	 *
	 * @param Sequence $sequence The Sequence containing the preparsed
	 * SingleResponse data.  If present, it will be used to initialize
	 * the object.
	 *
	 * @return SingleResponse  instance
	 */
	public function __construct( $sequence = null )
	{
		if ( isset( $sequence ) )
		{
			$this->setTLV( $sequence );
			$this->init( $sequence );
		}
	}

	/**
	 * Initialize the object from $sequence
	 *
	 * @param Sequence $sequence TLV containing the preparsed
	 * SingleResponse data
	 */
	protected function init( $sequence )
	{
		return $this->initFromTLV();
	}

	/**
	 * Set the data
	 *
	 * @param Sequwnce $sequence
	 * @return void
	 */
	public function setTLV( $sequence ) 
	{
		$this->_tlv = $sequence;
	}

	/**
	 * Get the details from the sequence
	 * @return void
	 */
	private function initFromTLV()
	{
		try 
		{
			/*
			 * We parse only thisUpdate and nextUpdate fields by default.
			 * Other fields are only parsed when requested by get* methods.
			 */
			$updateTime = \lyquidity\Asn1\asGeneralizedTime( $this->_tlv->getFirstChildOfType( UniversalTagID::GENERALIZEDTIME ) );
			$this->thisUpdate = $updateTime->getValue();

			$nextUpdate = \lyquidity\Asn1\asGeneralizedTime( $this->_tlv->getFirstChildOfType( 0, Element::CLASS_CONTEXTSPECIFIC, Tag::ENVIRONMENT_EXPLICIT ) );
			if ( $nextUpdate )
			{
				$this->nextUpdate = $nextUpdate->getValue();
			}
		}
		catch (\lyquidity\Asn1\Exception\Asn1DecodingException $e) 
		{
			throw new ResponseException("Malformed request", \lyquidity\OCSP\Ocsp::ERR_MALFORMED_ASN1);
		} 
		catch (\lyquidity\Asn1\Exception\InvalidAsn1Value $e)
		{
			throw new ResponseException("Malformed request", \lyquidity\OCSP\Ocsp::ERR_MALFORMED_ASN1);
		}
	}

	public function getThisUpdate()
	{
		return $this->thisUpdate;
	}

	public function getNextUpdate()
	{
		return $this->nextUpdate;
	}

	/**
	 * Return the CertID from the message.  The CertID will be read
	 * from the TLV if needed.
	 *
	 * @return array CertID (see \PKIX\OCSP\Request::parseCertID()
	 * for format description)
	 */
	public function getCertID()
	{
		if (!isset($this->CertID))
		{
			$this->CertID = Request::parseCertID($this->_tlv->first());
		}
		return $this->CertID;
	}

	/**
	 * Return the certStatus from the message.  The certStatus will be
	 * read from the TLV if needed.
	 *
	 * @return array CertStatus. The first element is the certificate
	 * status, which is one of:
	 * - \lyquidity\OCSP\Ocsp::CERT_STATUS_GOOD (0)
	 * - \lyquidity\OCSP\Ocsp::CERT_STATUS_REVOKED (1)
	 * - \lyquidity\OCSP\Ocsp::CERT_STATUS_UNKNOWN (2)
	 *
	 * In case of \lyquidity\OCSP\Ocsp::CERT_STATUS_REVOKED, the second
	 * element of CertStatus contains the revocationTime as
	 * DateTime. Otherwise, the second element of CertStatus is null.
	 */
	public function getCertStatus()
	{
		if ( ! isset( $this->certStatus ) )
		{
			$this->certStatus = $this->parseCertStatus();
		}
		return $this->certStatus;
	}

	private function parseCertStatus() 
	{
		$status = $this->_tlv->at(2);
		$certStatus = array( $status->getTypeID() );

		switch( $status->getTypeID() ) 
		{
			case \lyquidity\OCSP\Ocsp::CERT_STATUS_GOOD:
			case \lyquidity\OCSP\Ocsp::CERT_STATUS_UNKNOWN:
				array_push( $certStatus, null );
				break;
			case \lyquidity\OCSP\Ocsp::CERT_STATUS_REVOKED:
				$revokedInfo = asRawConstructed( $status );
				if ( ! $revokedInfo )
					throw new Asn1DecodingException('Expected information about the certificate\'s revokation');

				$revokedTime = \lyquidity\Asn1\asGeneralizedTime( $revokedInfo->getFirstChildOfType( UniversalTagID::GENERALIZEDTIME ) );
				if ( $revokedTime )
				{
					array_push( $certStatus, $revokedTime->getValue() );
				}

				$revokedReasonCode = \lyquidity\Asn1\asEnumerated( $revokedInfo->getFirstChildOfType( UniversalTagID::ENUMERATED ) );
				if ( $revokedReasonCode )
				{
					array_push( $certStatus, CRL::getRevokeReasonNameByCode( $revokedReasonCode->getValue() ) );
				}
				
				$time = \lyquidity\Asn1\asGeneralizedTime( $this->_tlv->getFirstChildOfType( UniversalTagID::GENERALIZEDTIME ) );
				if ( $time )
				{
					array_push( $certStatus, $time->getValue() );
				}
				break;
		}

		return $certStatus;
	}
}
