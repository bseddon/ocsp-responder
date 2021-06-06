# OCSP Responder

This project is a PHP implementation of [RFC 6960](https://datatracker.ietf.org/doc/html/rfc6960) to respond to X509 certificate checking by clients.  Example interfaces are provided to show how certificate status can be based on a JSON file store, an OpenSSL certificate database file and a MySQL table.

### Use case

The purpose of this responder is validate certificates you have created for clients that trust you.  For example, you might have an application that allows a user to sign an Xml document using an X509 so consumers of that document are able to verify the data contained in the Xml document has not been modified. Although the Xml document is signed by your application for your client, how does a consumer of a signed Xml document know the certificate used is valid?  The consumer can ask you to confirm the certificate used to sign a document is valid and not revoked by requesting an OCSP response from you, the author of the application used to sign the Xml document.

### Non-use case

The target use of this responder is not to get browsers to recognise certificates you generate.  Browsers include a bundle of certificates from well-known root certificate authorities such as Digicert,Let's Encrypt and others.  Although the responder will generate a valid response if asked by a browser, unless your CA certificate is signed by a well-known root certificate authority or a recognized intermediary, the browser will not validate certificates you create and sign if your certificate chain does not end at a well-known root certificate authority.

### Requirements

* Any HTTP server suitable for running PHP scripts.
* PHP version 7.3 or higher

### Source

This project is based on https://github.com/xperseguers/ocsp-responder which in turn is based on libpkix-asn1-php_1.0-6_all.deb available on http://pki.cesnet.cz/sw/ocsp.  Unlike these implementations that return pre-prepared responses (where do the responses come from?) it will generate an appropriate response based on information in a certificate store of some kind.

### Dependency

OCSP requests and responses take the form of DER encoded stream of [ASN.1](http://luca.ntop.org/Teaching/Appunti/asn1.html) tokens.  The code used to parse and write ASN.1 is in this [OCSP request](https://github.com/bseddon/ocsp) repository.

### Use

Make the URL used by a site for OCSP queries load the file ./src/OCSPServer.php.  The code in this file uses an OpenSSL file based CA in folder call 'certification/ca' but it can be changed.

Certificates you generate should include the address of your OCSP query endpoint, as a URL, in the Authority Information Access (AIA) X509 certificate extension.  The CA created by the [example code in the wiki](https://github.com/bseddon/ocsp-responder/wiki) does this.  The OCSP URL in the AIA extension is used by client to discover the address to which any OCSP request should be sent.

Follow the instructions in the wiki pages to use OpenSSL create a CA, generate 'foo', 'bar' and 'xxx' certificates then revoke the 'xxx' certificate.  Creating a CA using OpenSSL makes it easy to test and verify your setup.
