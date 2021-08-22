<?php

/*
 * PHP Response - OCSP Respone generator library for PHP
 */
namespace PKIX\OCSP;

use \lyquidity\Asn1\Element;
use \lyquidity\Asn1\Tag;
use \lyquidity\Asn1\UniversalTagID;
use PKIX\Exception\ResponseException;

use function \lyquidity\Asn1\asSequence;

/**
 * %OCSP response message.
 */
class Response extends \PKIX\Message
{
	const mimeType = 'application/ocsp-response';

	/** @var string[] */
	protected $knownResponses = array( \lyquidity\OCSP\Ocsp::id_pkix_ocsp_basic => '\PKIX\OCSP\BasicResponse');
	/** @var BasicResponse */
	protected $response;
	/** @var int */
	protected $maxage;

	/**
	 * Parse $data into internal object's structures.  Only information from the first SingleResponse is extracted.  Only
	 * information needed to generate HTTP response headers is extracted (producedAT, thisUpdate, nextUpdate).
	 *
	 * @param string $data DER-encoded ASN.1 OCSPResponse
	 */
	protected function init( $data )
	{
		try
		{
			/** @var Sequence */
			$this->_tlv = ( new \lyquidity\Asn1\Der\Decoder() )->decodeElement( $data );

			$enumerated = \lyquidity\Asn1\asEnumerated( $this->_tlv->getFirstChildOfType( UniversalTagID::ENUMERATED ) );
			$success = $enumerated ? $enumerated->getValue() === 0 : false;
		
			$responseBytes = asSequence( $this->_tlv->getFirstChildOfType(0, Element::CLASS_CONTEXTSPECIFIC, Tag::ENVIRONMENT_EXPLICIT ) );
			$responseType = $responseBytes ? \lyquidity\Asn1\asObjectIdentifier( $responseBytes->getFirstChildOfType( UniversalTagID::OBJECT_IDENTIFIER ) ) : null;

			$oid = $responseType ? $responseType->getIdentifier() : null;

			if ( $respClass = $this->knownResponses[ $oid ] ?? null )
			{
				$response = \lyquidity\Asn1\asOctetString( $responseBytes->getFirstChildOfType( UniversalTagID::OCTET_STRING ) );
			 	$this->response = new $respClass( $response->getValue() );
			}
		}
		catch (\lyquidity\Asn1\Exception\Asn1DecodingException $e) 
		{
			throw new ResponseException ("Malformed request", \lyquidity\OCSP\OCsp::ERR_MALFORMED_ASN1);
		} 
		catch (\lyquidity\Asn1\Exception\InvalidAsn1Value $e)
		{
			throw new ResponseException ("Malformed request", \lyquidity\OCSP\Ocsp::ERR_MALFORMED_ASN1);
		}
	}

	/**
	 * Date the response is created
	 *
	 * @return \DateTime
	 */
	public function getProducedAt()
	{
		return $this->response ? $this->response->getProducedAt() : new \DateTime("now");
	}

	public function getThisUpdate()
	{
		return $this->response->getThisUpdate();
	}

	public function getNextUpdate()
	{
		return $this->response ? $this->response->getNextUpdate() : null;
	}

	/**
	 * Return time-related information from the message (actually
	 * calling BasicResponse::getDates())
	 *
	 * @return array containing
	 * - producedAt - DateTime
	 * - thisUpdate - DateTime
	 * - nexUpdate - DateTime
	 */
	public function getDates()
	{
		return $this->response->getDates();
	}

	/**
	 * Set maximum time for the message to be cached (used by
	 * respondHeaders()).  When sendind the message as HTTP request,
	 * the 'Cache-Control' header's 'max-age' parameter will not be
	 * larger than $maxage.
	 *
	 * @param int $maxage The maximum caching time in seconds
	 */
	public function setMaxAge($maxage)
	{
		$this->maxage = $maxage;
	}

	/**
	 * Return the CertID from the first SingleResponse in the
	 * message. Actually calls the BasicResponse::getCertID().
	 *
	 * @return array CertID (see \\PKIX\\OCSP\\Request::parseCertID()
	 * for format description)
	 */
	public function getCertID()
	{
		return $this->response->getCertID();
	}

	/**
	 * Return the certStatus from the first SignleResponse in the
	 * message. Actually calls the BasicResponse::getCertID().
	 *
	 * @return array CertStatus. The first element is the certificate
	 * status, which is one of:
	 * - \\PKIX\\OCSP\\CERT_STATUS_GOOD (0)
	 * - \\PKIX\\OCSP\\CERT_STATUS_REVOKED (1)
	 * - \\PKIX\\OCSP\\CERT_STATUS_UNKNOWN (2)
	 *
	 * In case of \\PKIX\\OCSP\\CERT_STATUS_REVOKED, the second
	 * element of CertStatus contains the revocationTime as
	 * DateTime. Othewise, the second element of CertStatus is null.
	 */

	public function getCertStatus() 
	{
		return $this->response->getCertStatus();
	}

	/**
	 * Verify the message signature using the $signer certificate.  When $signer is not set, tries consecutively all signer 
	 * certificates from the message.  Return an array containing all certificates for which the signature has been succesully
	 * verified.
	 *
	 * @param string $signer The signer certificate.  If not set, all potential signer certificates from the message are tried.
	 * @return string[] The certificates for which the signature  verification has been successful.
	 *
	 * @throws \PKIX\Exception\UnimplementedException on unsupported signature algorithm
	 */
	public function verifySignature( $signer = null )
	{
		return $this->response->verifySignature( $signer );
	}

	/**
	 * Return serialized representation of the part of the message inteded to be signed.
	 *
	 * @return string ASN.1 binary string suitable for signing/verifying the signature
	 * @throws \PKIX\Exception\UnimplementedException when not implemented by the called class
	 */
	public function getSignedData()
	{
		return $this->response->getSignedData();
	}

	/* HTTP interface */
	/* doc inherited     */
	public function respondHeaders()
	{
		$h = array(
			'Content-Type' => static::mimeType,
			'Content-Length' => strlen($this->getData()),
			'ETag' => '"' . sha1( $this->getData() ) . '"',
			'Last-Modified' => $this->getProducedAt()->format( $this->dtfmt ) );
		if ( $this->getNextUpdate() )
		{
			$h['Expires'] = $this->getNextUpdate()->format( $this->dtfmt );
		}
		$h['Cache-Control'] = $this->getCacheControl();

		return $h;
	}

	/**
	 * Generate and return the 'Cache-Control' HTTP header according
	 * to RFC5019.
	 *
	 * @return string Value of the the Cache-Control header
	 */
	private function getCacheControl()
	{
		$now = time();
		$nextUp = $this->getNextUpdate() ? $this->getNextUpdate()->format('U') : time();
		$diff = $nextUp - $now;

		if ($diff < 0) 
		{
			$diff = 0;
			$CertID = $this->getCertID();
			error_log("stale response for serial $CertID[serialNumber] (issuerNameHash: $CertID[issuerNameHash], issuerKeyHash: $CertID[issuerKeyHash])");
		}

		if (isset($this->maxage)) 
		{
			if ($this->maxage > $diff)
			{
				$ma = $diff;
			}
			else
			{
				$ma = $this->maxage;
			}
		}
		else
		{
			$ma = $diff;
		}

		return "max-age=" . $ma . ",public,no-transform,must-revalidate";
	}
}
