<?php
/*
 * PKIX ASN.1 Message - Abstract class for manipulating ASN.1 messages.
 * Also provides functions for exchanging these messages over HTTP.
 */

namespace PKIX;

use \lyquidity\Asn1\Element\Sequence;
use \PKIX\Exception\HTTPException;
use PKIX\Exception\RequestException;
use \PKIX\Exception\UnimplementedException;

/**
 * Abstract class for manipulating PKIX ASN1 Messages.
 *
 * Also provides functions for exchanging these messages over HTTP.
 *
 * Subclasses must implement the actual structure parsing function init().
 *
 */
abstract class Message
{
	const HTTP_OK = 200;
	const HTTP_BAD_REQUEST = 400;
	const HTTP_METHOD_NOT_ALLOWED = 405;
	const HTTP_UNSUPPORTED_MEDIA_TYPE = 415;
	const HTTP_INTERNAL_SERVER_ERROR = 500;

	const mimeType = 'application/ocsp-request';

	/** @var Sequence */
	protected $_tlv;
	/** @var string */
	protected $dtfmt = 'D, d M Y H:i:s O';
	/** @var string */
	protected $data;

	/**
	 * Constructor
	 *
	 * @param $data DER encoded ASN.1 string. If provided, the class'  init() function will
	 * 				be called to parse the $data into the object's internal structures.
	 * @throws \PKIX\Exception\MessageException or its subclass
	 */
	public function __construct($data = null)
	{
		if ( isset( $data ) )
		{
			$this->setData( $data, true) ;
		}
	}

	/**
	 * Implement the actual parser for the PKIX\ASN1\Message subclass.
	 *
	 * @param $data DER encoded ASN.1 string to parse
	 * @throws \PKIX\Exception\MessageException or its subclass
	 *
	 */
	abstract protected function init( $data );

	/**
	 * @return string DER-encoded ASN.1 serialization of the message.
	 */
	public function getData() 
	{
		// Debug only
		// $decode = (new \Ocsp\Asn1\Der\Decoder())->decodeElement($this->data);
		return $this->data;
	}

	/**
	 * Set the ASN.1 data for the message.
	 *
	 * @param $data DER-encoded ASN.1 string
	 * @param $parse If set to true, the $data will be parsed into object's internal structures
	 * @throws \PKIX\Exception\MessageException or its subclass
	 */
	public function setData($data, $parse = null)
	{
		$this->data = $data;
		if ($parse)
		{
			$this->init($data);
		}
		return $this;
	}

	/**
	 * Verify the message signature using the $signer certificate.  When $signer is not set, tries consecutively all signer 
	 * certificates from the message.  Return an array containing all certificates for which the signature has been succesully
	 * verified.
	 *
	 * @param string $signer The signer certificate.  If not set, all potential signer certificates from the message are tried.
	 *
	 * @return array The certificates for which the signature  verification has been successful.
	 *
	 * @throws \PKIX\Exception\UnimplementedException on unsupported signature algorithm
	 */
	public function verifySignature( $signer = null )
	{
		$signedData = $this->getSignedData();
		$signers = \lyquidity\OCSP\Ocsp::verifySigning( $this->_tlv, $signer, $signedData );
	}

	/**
	 * Return serialized representation of the part of the message intended to be signed.
	 *
	 * @return string ASN.1 binary string suitable for signing/verifying the signature
	 * @throws \PKIX\Exception\UnimplementedException when not implemented by the called class
	 */
	public function getSignedData()
	{
		throw new UnimplementedException(get_called_class()	. "::getSignedData() not implemented");
	}

	/** end of Signature Verification */

	/** @name HTTP Interface
	 *
	 * PKIX\Message provides a simple interface for trasporting
	 * ASN.1 messages over HTTP.  The interface enables acting as
	 * an HTTP server -- receiving and respondig the messages
	 * (receive() and respond() methods).  In addition, sending
	 * messages to an HTTP server and fetching its reponses is
	 * supported as well (send(), GET() and POST() methods).
	 */

    /**
	 * Get message from the HTTP request trying HTTP methods specified
	 * in $methods.  The 'GET' method expects the data as urlencoding
	 * of base64-encoded ASN.1 message appended to the script name
	 * accorging to RFC5019.  The 'POST' method reads the data from
	 * the HTTP request body after checking the body's Content-Type
	 * header.  The Content-Type must match the class' mimeType
	 * property.
	 *
	 * @param array $methods The methods in the array are tried in
	 * sequence to read the message.  Only 'GET' and 'POST' methods
	 * are supported.
	 *
	 * @return string The received message (unencoded)
	 *
	 * @throws \PKIX\Exception\HTTPException
	 */
    public static function receive(array $methods)
	{
		if (in_array($_SERVER['REQUEST_METHOD'], $methods))
		{
			switch( $_SERVER['REQUEST_METHOD'] )
			{
				case 'POST':

					if ($_SERVER['CONTENT_TYPE'] != self::mimeType)
					{
						throw new HTTPException ("POST body is not application/ocsp-request",
							self::HTTP_UNSUPPORTED_MEDIA_TYPE);
					}
					$rdata = file_get_contents("php://input");
					break;

				case 'GET':
					if ( $_SERVER['REQUEST_METHOD'] == 'GET' )
					{
						if ( isset( $_SERVER['PATH_INFO'] ) )
						{
							$d = $_SERVER['PATH_INFO'];
							//	      error_log ("receive: d='$d'");
							/* Clients tend to accumulate slahes in front of the
							 actual request */
							for ($i = 0;
								 $i < strlen($d) && $d[$i] === '/';
								 $i++) {
							}

							$d = rawurldecode($d);

							/* By how many chars is $d longer than a multiple of four? */
							$over4 = strlen($d) % 4;

							/* Remove $over4 (but at most $i) leading slashes */
							if ($over4 <= $i)
							{
								$d = substr($d, $over4); /* remove the leading '/' */
							}
							$rdata = base64_decode(rawurldecode($d), 1);
						}
					}
					break;

				default:
					throw new RequestException('Unimplemented receive method: '
						. $_SERVER['REQUEST_METHOD']);
			}
		}
		else
		{
			throw new HTTPException('Unsupported HTTP method',
				self::HTTP_METHOD_NOT_ALLOWED);
		}

		if ( ! isset( $rdata ) || strlen( $rdata ) < 1 ) 
		{
			throw new HTTPException("Empty request", self::HTTP_BAD_REQUEST);
		}

		//      error_log(get_class()."::receive(): rdata[".strlen($rdata)."]: $rdata");
		return $rdata;
	}

    /**
	 * Send this message to the client wrapped as HTTP response.
	 */
    public function respond()
	{
		if ( isset( $this->HTTPStatus ) )
		{
			header($this->HTTPStatusHeader());
		}
		$headers = $this->respondHeaders();
		foreach( $headers as $k => $v )
		{
			header("$k: $v");
		}
		echo $this->getData();
	}

    /**
	 * Return HTTP headers to be used by the respond() method.
	 *
	 * @return array HTTP headers
	 */
    public function respondHeaders()
	{
		return array('Content-Type' => static::mimeType);
	}

    /**
	 * Return HTTP status header based on the HTTPStatus property
	 * value
	 *
	 * @return string HTTP status header corrsponding to the value of
	 * HTTPStatus attribute, null otherwise
	 */
    public function HTTPStatusHeader()
	{
		if (isset($this->HTTPStatus)) {
			return $_SERVER['SERVER_PROTOCOL'] . ' ' . $this->HTTPStatus;
		}
	}
    /**
	 * Send the message using HTTP to the $url using the $method
	 * (actually calling the GET() or POST() method)
	 *
	 * @param string $url HTTP URL to send the message to
	 *
	 * @param string $method The HTTP method to use
	 *
	 * @return array
	 * The returned array contains the HTTP
	 * response.  The respone body is available at the 'body' key and
	 * the response headers at the 'headers' key.
	 *
	 * @throws \HTTPException on bad parameter
	 */
    public function send( $url, $method = 'POST'  )
	{
		if ( $method == 'POST')
		{
			return $this->POST($url);
		}
		elseif ($method == 'GET')
		{
			return $this->GET($url);
		}
		else
		{
			throw new HTTPException(get_class()
				. "::send: Bad Parameter $method");
		}
	}

    /**
	 * Send this message to $url using HTTP GET
	 *
	 * @param string $url The URL to send to
	 * @return array  The returned array contains the HTTP
	 * response.  The respone body is available at the 'body' key and
	 * the response headers at the 'headers' key.
	 *
	 */
    public function GET( $url )
	{
		$b = rawurlencode(base64_encode($this->getData()));
		$result = file_get_contents($url . "/" . $b);
		$resp_head = $http_response_header;
		return array('body' => $result,
			'headers' => $resp_head);
	}

    /**
	 * Send this message to $url using HTTP POST
	 *
	 * @param string $url The URL to send to
	 * @return array The returned array contains the HTTP
	 * response.  The respone body is available at the 'body' key and
	 * the response headers at the 'headers' key.
	 */
    public function POST($url)
	{
		$headers = '';
		$hs = $this->getPOSTHeaders();
		foreach ($hs as $h => $v)
		{
			$headers .= "$h: $v\r\n";
		};

		$opts =
			array('http' =>
				array('method' => 'POST',
					'header' => $headers,
					'content' => $this->getData())
			);

		$context = stream_context_create($opts);
		$result = file_get_contents($url, false, $context);
		$resp_head = $http_response_header;

		return array('body' => $result,
			'headers' => $resp_head);
	}

    /**
	 * Return HTTP headers for sending this message using POST
	 *
	 * @return array The HTTP headers
	 */
    public function getPOSTHeaders()
	{
		return array('Content-Type' => static::mimeType);
	}
    /**@} end of HTTP interface*/

    /** @name Utilities
	 * Several utilities for data conversion
	 */
    /**@{*/

    /**
	 * Convert a number from hexadecimal to decimal representation.
	 *
	 * @param string $hex hexadecimal representation of a number
	 * @return string decimal representation
	 */
    public static function bchexdec( $hex )
	{
		if ( strlen( $hex ) == 1 )
		{
			return hexdec($hex);
		}
		else
		{
			$remain = substr($hex, 0, -1);
			$last = substr($hex, -1);
			return bcadd(bcmul(16, self::bchexdec($remain)), hexdec($last));
		}
	}

    /**
	 * Convert a number from decimal to hexadecimal representation.
	 *
	 * @param string $dec decimal representation of a number
	 * @return string hexadecimal representation
	 */
    public static function bcdechex( $dec )
	{
		$last = bcmod($dec, 16);
		$remain = bcdiv(bcsub($dec, $last), 16);

		if ( $remain == 0 )
		{
			return dechex($last);
		}
		else
		{
			return self::bcdechex($remain) . dechex($last);
		}
	}

    /**
	 * Convert binary (DER) ASN.1 string to PEM format.  The data is
	 * base64-encoded and wrapped in a header ('-----BEGIN
	 * $type-----') and a footer ('-----END $type-----').  The
	 * conversion is required by PHP openssl_* functions for
	 * key-containing parameters.
	 *
	 * @param string $data DER-encode binary data
	 * @param string $type object type (i. e. 'CERTIFICATE', 'RSA
	 * PUBLIC KEY', etc.
	 *
	 * @return string data in PEM format
	 */
    static public function PEMize( $data, $type )
	{
		return "-----BEGIN $type-----\r\n"
		. chunk_split(base64_encode($data))
		. "-----END $type-----\r\n";
	}

    /**@} end of utilities*/
}
