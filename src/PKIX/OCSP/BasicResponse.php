<?php
/*
 * PHP OCSPRequest - OCSP Request access library for PHP
 */
namespace PKIX\OCSP;

use \lyquidity\Asn1\Element\Sequence;
use \lyquidity\Asn1\UniversalTagID;
use PKIX\Exception\ResponseException;

use function \lyquidity\Asn1\asSequence;

/**
 * BasicResponse message (see RFC2560)
 */
class BasicResponse extends \PKIX\Message
{
	/** "var DateTime */
	protected $producedAt;
	/** @var SingleResponse[] */
	protected $responses;
	/** @var SingleResponse */
	protected $singleResponse;    /**< the first PKIX::ASN1::SingleResponse */

	/**
	 * Parse $data into internal object's structures. Only
	 * information from the first SingleResponse is extracted. Only
	 * information needed generate HTTP response headers is extracted
	 * (producedAT, thisUpdate, nextUpdate).
	 *
	 * @param string $data DER-encoded ASN.1 BasicResponse
	 */
	protected function init( $data )
	{
		try
		{
			/** @var Sequence */
			$this->_tlv = ( new \lyquidity\Asn1\Der\Decoder() )->decodeElement( $data );

			$tbsResponseData = $this->_tlv->first()->asSequence();
			$dateTime = \lyquidity\Asn1\asGeneralizedTime( $tbsResponseData->getFirstChildOfType( UniversalTagID::GENERALIZEDTIME ) );
			// $this->producedAt = $this->DateTimefromString( $dateTime );
			$this->producedAt = $dateTime->getValue();

			$this->responses = asSequence( $tbsResponseData->getFirstChildOfType( UniversalTagID::SEQUENCE ) );

			/* We care only about the first SingleResponse */
			$this->singleResponse = new SingleResponse( $this->responses->first() );
		}
		catch (\lyquidity\Asn1\Exception\Asn1DecodingException $e) 
		{
			throw new ResponseException ("Malformed request", \lyquidity\OCSP\Ocsp::ERR_MALFORMED_ASN1);
		} 
		catch (\lyquidity\Asn1\Exception\InvalidAsn1Value $e)
		{
			throw new ResponseException ("Malformed request", \lyquidity\OCSP\Ocsp::ERR_MALFORMED_ASN1);
		}
	}

	/**
	 * The time the response was produced or now
	 * @return DataTime 
	 */
	public function getProducedAt()
	{
		return $this->producedAt ?? new \DateTime("now");
	}

	public function getThisUpdate()
	{
		return $this->singleResponse->getThisUpdate();
	}

	public function getNextUpdate()
	{
		return $this->singleResponse->getNextUpdate();
	}

	/**
	 * Return time-related information from the message.
	 *
	 * @return array containing
	 * - producedAt - DateTime
	 * - thisUpdate - DateTime
	 * - nexUpdate - DateTime
	 */
	public function getDates()
	{
		return array(
			'producedAt' => $this->producedAt,
			'thisUpdate' => $this->getThisUpdate(),
			'nextUpdate' => $this->getNextUpdate()
		);
	}

	/**
	 * Return the CertID from the first SingleResponse in the
	 * message. Actually calls the SingleResponse::getCertID().
	 *
	 * @return array CertID (see \\PKIX\\OCSP\\Request::parseCertID()
	 * for format description)
	 *
	 */
	public function getCertID()
	{
		return $this->singleResponse->getCertID();
	}

	/**
	 * Return the certStatus from the first SignleResponse in the
	 * message. Actually calls the BasicResponse::getCertID().
	 *
	 * @return array CertStatus. The first element is the certificate
	 * status, which is one of:
	 * - \Ocsp\Ocsp::CERT_STATUS_GOOD (0)
	 * - \Ocsp\Ocsp::CERT_STATUS_REVOKED (1)
	 * - \Ocsp\Ocsp::CERT_STATUS_UNKNOWN (2)
	 *
	 * In case of \Ocsp\Ocsp::CERT_STATUS_REVOKED, the second
	 * element of CertStatus contains the revocationTime as
	 * DateTime. Othewise, the second element of CertStatus is null.
	 *
	 */
	public function getCertStatus()
	{
		return $this->singleResponse->getCertStatus();
	}

	/** @name Signature Verification (Local implementation)
	 *
	 * Local implementation of signature verification related methods
	 **@{
	 */

	/**
	 * Return serialized representation of the part of the message intended to be signed.
	 *
	 * @return string ASN.1 binary string suitable for signing/verifying the signature
	 * @throws \PKIX\Exception\UnimplementedException when not implemented by the called class
	 */
	public function getSignedData()
	{
		// Don't think this is right but need an example
        return ( new \lyquidity\Asn1\Der\Encoder() )->encodeElement( $this->_tlv->first() );
	}

	/**
	 * Verify the message signature using the $signer certificate.  When $signer is not set, tries consecutively all signer 
	 * certificates from the message.  Return an array containing all certificates for which the signature has been succesully
	 * verified.
	 *
	 * @param string $signer The signer certificate.  If not set, all potential signer certificates from the message are tried.
	 * @return string[] The certificates for which the signature  verification has been successful.
	 * @throws \PKIX\Exception\UnimplementedException on unsupported signature algorithm
	 */
	public function verifySignature( $signer = null )
	{
		// $signedData = $this->getSignedData();
		$signers = \lyquidity\OCSP\Ocsp::verifySigning( $this->_tlv, $signer, $signer );
		return $signers;
	}
	/*@} end of Signature Verification (Local implementation) */
}
