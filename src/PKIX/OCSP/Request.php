<?php
/*
 * PHP OCSPRequest - OCSP Request access library for PHP
 */
namespace PKIX\OCSP;

use Ocsp\Asn1\Element;
use Ocsp\Asn1\Element\Integer;
use Ocsp\Asn1\Element\ObjectIdentifier;
use Ocsp\Asn1\Element\OctetString;
use Ocsp\Asn1\Element\Sequence;
use Ocsp\Asn1\Tag;
use Ocsp\Asn1\UniversalTagID;
use PKIX\Exception\RequestException;

use const Ocsp\ERR_MALFORMED_ASN1;
use const Ocsp\ERR_REQLIST_EMPTY;
use const Ocsp\ERR_REQLIST_MULTI;
use const Ocsp\ERR_UNSUPPORTED_EXT;

/**
 * %OCSP request message
 *
 */
class Request extends \PKIX\Message
{
	protected $CertID;

	/**
	 * Parse $data into internal object's structures.  Only
	 * information needed to identify the requested response is
	 * extracted.  This is actually just the CertID (RFC2560)
	 * structure.  Only the first request of the requestList is
	 * extracted.
	 *
	 * @param string $data DER-encoded ASN.1 OCSPRequest
	 * @throws \PKIX\OCSP\Exception
	 */
	protected function init($data)
	{
		try 
		{
			$this->_tlv = ( new \Ocsp\Asn1\Der\Decoder() )->decodeElement( $data );

			// The request structure has sequences nested 4 deep before reaching the values needed for verification
			$tbsRequest = $this->_tlv->first()->asSequence();
			/** @var Integer */
			$version = $tbsRequest->getFirstChildOfType( UniversalTagID::INTEGER, Element::CLASS_CONTEXTSPECIFIC );
			if ($version != null && $version->getValue() != 0 ) 
			{
				throw new RequestException("Unsupported OCSPRequest message version", \Ocsp\Ocsp::ERR_UNSUPPORTED_VERSION);
			}

			/* skipped: requestorName */

			/* requestExtensions: nonce, AcceptableResponseTypes, ServiceLocator
			 * Find out if any critical extension is requested.
			 * RFC2560 says there should be none but in case there are some
			 * we should give up as we don't support any extension ;)
			*/
			/** @var Sequence */
			$requestExtensions = $tbsRequest->getFirstChildOfType( UniversalTagID::SEQUENCE, Element::CLASS_CONTEXTSPECIFIC );
			if ( $requestExtensions )
			{
				$extensions = $requestExtensions->first()->asSequence();
				foreach ($extensions->getElements() as $i => $extension)
				{
					/** @var Sequence $extension */
					$extoid = \Ocsp\Asn1\asObjectIdentifier( $extension->first() )->getIdentifier();
					$critical = \Ocsp\Asn1\asBoolean( $extension->getFirstChildOfType( UniversalTagID::BOOLEAN ) );
					if ( $critical && $critical->getValue() )
					{
						throw new RequestException ("Unsupported critical extension $extoid", \Ocsp\Ocsp::ERR_UNSUPPORTED_EXT);
					}
				}
			}

			$requestList = $tbsRequest->getFirstChildOfType( UniversalTagID::SEQUENCE )->asSequence();

			$reqCnt = count( $requestList->getElements() );
			if ($reqCnt == 0)
			{
				throw new RequestException ("No certificate status requested", \Ocsp\Ocsp::ERR_REQLIST_EMPTY );
			}
			if ($reqCnt > 1)
			{
				throw new RequestException ("Multiple certificate status requested", \Ocsp\Ocsp::ERR_REQLIST_MULTI );
			}

			$request = $requestList->first()->asSequence();

			/** @var Sequence */
			$singleRequestExtensions = $request->getFirstChildOfType( 0, Element::CLASS_CONTEXTSPECIFIC, Tag::ENVIRONMENT_EXPLICIT );
			if ( $singleRequestExtensions != null ) 
			{
				/* check for critical extensions, break if found some*/
				foreach( $singleRequestExtensions->getElements() as $extension) 
				{
					/** @var Sequence $extension */
					$extoid = \Ocsp\Asn1\asObjectIdentifier( $extension->first() )->getIdentifier();
					$critical = \Ocsp\Asn1\asBoolean( $extension->getFirstChildOfType( UniversalTagID::BOOLEAN ) );
					if ( $critical && $critical->getValue() )
					{
						throw new RequestException( "Unsupported critical extension $extoid", \Ocsp\Ocsp::ERR_UNSUPPORTED_EXT );
					}
				}
			}

			$this->CertID = self::parseCertID( $request->first()->asSequence() );
		}
		catch (\Ocsp\Exception\Asn1DecodingException $e) 
		{
			throw new RequestException ("Malformed request", \Ocsp\Ocsp::ERR_MALFORMED_ASN1 );
		} 
		catch (\Ocsp\Exception\InvalidAsn1Value $e)
		{
			throw new RequestException ("Malformed request", \Ocsp\Ocsp::ERR_MALFORMED_ASN1 );
		}
	}

	/**
	 * Parse a CertID TLV
	 *
	 * @param Sequence $CID
	 * @return array The returned array contains four fields
	 * identifying a certificate:
	 * - hashAlgorithm - string representaion of the hash algorithm OID
	 * - issuerNameHash - hex representation of issuerNameHash
	 * - issuerKeyHash - hex representation of issuerkeyHash
	 * - serialNumber - the certificate serial number
	 */
	static function parseCertID( $CID )
	{
		$CertID = array();
		$keys = array(
			'hashAlgorithm',
			'issuerNameHash',
			'issuerKeyHash',
			'serialNumber'
		);

		$CertID[ $keys[ 0 ] ] = \Ocsp\Asn1\asObjectIdentifier( $CID->at(1)->asSequence()->at(1) )->getIdentifier();
		$CertID[ $keys[ 1 ] ] = \Ocsp\Asn1\asOctetString( $CID->at(2) )->getValue();
		$CertID[ $keys[ 2 ] ] = \Ocsp\Asn1\asOctetString( $CID->at(3) )->getValue();
		$CertID[ $keys[ 3 ] ] = \Ocsp\Asn1\asInteger( $CID->at(4) )->getEncodedValue( new \Ocsp\Asn1\Der\Encoder() );

		return $CertID;
	}

	/**
	 * Return the reqCert of the first request in the message
	 *
	 * @return array CertID (see parseCertID())
	 */
	public function getCertID()
	{
		return $this->CertID;
	}

	/**
	 * Create a new \\PKIX\\OCSP\\Request from parameters provided in $params.
	 * The request is minimal but compliant with RFC5019 and can be
	 * used to query an OCSP server.
	 *
	 * @param string[] $params The array represents the requested
	 * certificate in the from of the CertID. See parseCertID() for
	 * description.
	 */
	public function createFromParams( $params )
	{
		/*
		OCSPRequest     ::=     SEQUENCE {
		tbsRequest                  TBSRequest,
		optionalSignature   [0]     EXPLICIT Signature OPTIONAL }

		TBSRequest      ::=     SEQUENCE {
		version             [0] EXPLICIT Version DEFAULT v1,
		requestorName       [1] EXPLICIT GeneralName OPTIONAL,
		requestList             SEQUENCE OF Request,
		requestExtensions   [2] EXPLICIT Extensions OPTIONAL }

		Signature       ::=     SEQUENCE {
		signatureAlgorithm   AlgorithmIdentifier,
		signature            BIT STRING,
		certs                [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }

		Version  ::=  INTEGER  {  v1(0) }

		Request ::=     SEQUENCE {
		reqCert                    CertID,
		singleRequestExtensions    [0] EXPLICIT Extensions OPTIONAL }
		  */

		$hashAlgorithm = Sequence::create([
            // OBJECT IDENTIFIER [algorithm]
            ObjectIdentifier::create( $params['hashAlgorithm'] ) // eg SHA1
        ]);
        $requestList = new Sequence();
		$requestList->addElement(
			// Request
			Sequence::create([
				// CertID [reqCert]
				Sequence::create([
					// AlgorithmIdentifier [hashAlgorithm]
					$hashAlgorithm,
					// OCTET STRING [issuerNameHash]
					OctetString::create( $params['issuerNameHash'], true ),
					// OCTET STRING [issuerKeyHash]
					OctetString::create( $params['issuerKeyHash'] ),
					// CertificateSerialNumber [serialNumber]
					Integer::create( $params['serialNumber'] ),
				]),
			])
		);

        $data = $this->derEncoder->encodeElement(
            // OCSPRequest
            Sequence::create([
                // TBSRequest [tbsRequest]
                Sequence::create([
                    $requestList,
                ]),
            ])
        );

		return new self( $data );
	}
}
