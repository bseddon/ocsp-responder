<?php
/*
 * PHP SingleResponse - OCSP response for a specific certificate validation request
 */
namespace PKIX\OCSP;

use Ocsp\Asn1\Element;
use Ocsp\Asn1\Element\GeneralizedTime;
use Ocsp\Asn1\Tag;
use Ocsp\Asn1\UniversalTagID;
use Ocsp\Exception\Asn1DecodingException;
use PKIX\CRL;
use PKIX\Exception\ResponseException;

use function Ocsp\Asn1\asRawConstructed;

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
			$updateTime = \Ocsp\Asn1\asGeneralizedTime( $this->_tlv->getFirstChildOfType( UniversalTagID::GENERALIZEDTIME ) );
			$this->thisUpdate = $updateTime->getValue();

			$nextUpdate = \Ocsp\Asn1\asGeneralizedTime( $this->_tlv->getFirstChildOfType( 0, Element::CLASS_CONTEXTSPECIFIC, Tag::ENVIRONMENT_EXPLICIT ) );
			if ( $nextUpdate )
			{
				$this->nextUpdate = $nextUpdate->getValue();
			}
		}
		catch (\Ocsp\Exception\Asn1DecodingException $e) 
		{
			throw new ResponseException("Malformed request", ERR_MALFORMED_ASN1);
		} 
		catch (\Ocsp\Exception\InvalidAsn1Value $e)
		{
			throw new ResponseException("Malformed request", ERR_MALFORMED_ASN1);
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
	 * - \PKIX\OCSP\CERT_STATUS_GOOD (0)
	 * - \PKIX\OCSP\CERT_STATUS_REVOKED (1)
	 * - \PKIX\OCSP\CERT_STATUS_UNKNOWN (2)
	 *
	 * In case of \PKIX\OCSP\CERT_STATUS_REVOKED, the second
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
			case CERT_STATUS_GOOD:
			case CERT_STATUS_UNKNOWN:
				array_push( $certStatus, null );
				break;
			case CERT_STATUS_REVOKED:
				$revokedInfo = asRawConstructed( $status );
				if ( ! $revokedInfo )
					throw new Asn1DecodingException('Expected information about the certificate\'s revokation');

				$revokedTime = \Ocsp\Asn1\asGeneralizedTime( $revokedInfo->getFirstChildOfType( UniversalTagID::GENERALIZEDTIME ) );
				if ( $revokedTime )
				{
					array_push( $certStatus, $revokedTime->getValue() );
				}

				$revokedReasonCode = \Ocsp\Asn1\asEnumerated( $revokedInfo->getFirstChildOfType( UniversalTagID::ENUMERATED ) );
				if ( $revokedReasonCode )
				{
					array_push( $certStatus, CRL::getRevokeReasonNameByCode( $revokedReasonCode->getValue() ) );
				}
				
				$time = \Ocsp\Asn1\asGeneralizedTime( $this->_tlv->getFirstChildOfType( UniversalTagID::GENERALIZEDTIME ) );
				if ( $time )
				{
					array_push( $certStatus, $time->getValue() );
				}
				break;
		}

		return $certStatus;
	}
}
