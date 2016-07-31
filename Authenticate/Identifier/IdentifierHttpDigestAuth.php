<?php
namespace Poirot\AuthSystem\Authenticate\Identifier;

use Poirot\AuthSystem\Authenticate\Identity\IdentityHttpDigest;
use Poirot\AuthSystem\Authenticate\Identity\IdentityUsername;
use Poirot\AuthSystem\Authenticate\Interfaces\iIdentity;

use \Poirot\AuthSystem\Authenticate\Identifier\HttpDigest;

/*
$request = new P\Http\HttpRequest(new P\Http\HttpMessage\Request\DataParseRequestPhp);
$response = new P\Http\HttpResponse(new P\Http\HttpMessage\Response\DataParseResponsePhp());

$adapter = new P\AuthSystem\Authenticate\RepoIdentityCredential\IdentityCredentialDigestFile();
$authenticator = new P\AuthSystem\Authenticate\Authenticator(
    new P\AuthSystem\Authenticate\Identifier\IdentifierHttpDigestAuth('Default_Auth', [
        'request'            => $request,
        'response'           => $response,
        'credential_adapter' => $adapter,
    ])
    ## identity credential repository
    ,  $adapter
);

try {
    if (!$authenticator->hasAuthenticated())
        throw new P\AuthSystem\Authenticate\Exceptions\exAuthentication($authenticator);

    echo 'program continue run..';

    // signout
    #$authenticator->identifier()->signOut();

} catch (P\AuthSystem\Authenticate\Exceptions\exAuthentication $e)
{
    $e->issueException();
}

P\Http\HttpMessage\Response\Plugin\PhpServer::_($response)->send();
*/

class IdentifierHttpDigestAuth
    extends IdentifierHttpBasicAuth
{
    // Options
    protected $nonceTimeout = 300;
    protected $nonce_secret = 'nonce_secret_key';

    /** @var string space-separated list of URIs, define the protection space */
    protected $domains;
    /** @var string The actual algorithm to use. Defaults to MD5 */
    protected $defaultAlgorithm = 'MD5';
    /**
     * List of supported qop options. My intention is to support both 'auth' and
     * 'auth-int', but 'auth-int' won't make it into the first version.
     */
    protected $supportedQops = array('auth');
    protected $useOpaque     = true;


    /**
     * Can Recognize Identity?
     *
     * note: never check remember flag
     *   the user that authenticated with
     *   Remember Me must recognized when
     *   exists.
     *
     * @return boolean
     */
    function canRecognizeIdentity()
    {
        return (boolean) HttpDigest\hasAuthorizationHeader($this->request(), $this->isProxyAuth());
    }

    /**
     * Attain Identity Object From Signed Sign
     * exp. session, extract from authorize header,
     *      load lazy data, etc.
     *
     * !! called when user is signed in to retrieve user identity
     *
     * note: almost retrieve identity data from cache or
     *       storage that store user data. ie. session
     *
     * @return null|iIdentity|\Traversable Null if no change need
     * @throws \Exception
     */
    protected function doRecognizedIdentity()
    {
        $headerValue = HttpDigest\hasAuthorizationHeader($this->request(), $this->isProxyAuth());

        /* TODO
         * If a directive or its value is improper, or required directives are
         * missing, the proper response is 400 Bad Request. If the request-
         * digest is invalid, then a login failure should be logged, since
         * repeated login failures from a single client may indicate an attacker
         * attempting to guess passwords.
         */
        $headerData = HttpDigest\parseDigestAuthorizationHeader($headerValue);

        if (!in_array($headerData['qop'], $this->supportedQops))
            ## TODO not support challenge again with alternative if exists
            throw new \Exception(sprintf('"qop"(%s) not support.', $headerData['qop']));

        if ($this->_generateNonce() != $headerData['nonce'])
            ## client sent back same nonce
            return false;


        // If the server sent an opaque value, the client must send it back
        if ($this->isUseOpaque()) {
            // Validate Opaque
            if (!isset($headerData['opaque']))
                return false;
            elseif ($this->_generateOpaque() != $headerData['opaque'])
                return false;
        }


        // ...

        /*
         * A1 = md5(username:realm:password)
         * A2 = md5(request-method:uri) // request method = GET, POST, etc.
         * Hash = md5(A1:nonce:nc:cnonce:qop:A2)
         * if (Hash == response)
         *    //success!
         */

        /** @var IdentityHttpDigest $digestIdentity */
        $credentialAdapter = $this->credentialAdapter;
        if (!$credentialAdapter)
            throw new \Exception('Credential Adapter Repository not defined.');

        $credentialAdapter->setRealm($this->getRealm());
        $credentialAdapter->import(array('username' => $headerData['username']));
        $digestIdentity = $credentialAdapter->findIdentityMatch();
        if (!$digestIdentity)
            // User not recognized!
            return false;

        $digestIdentity = new IdentityHttpDigest($digestIdentity);

        $ha1 = $digestIdentity->getA1();

        $algorithm = (
            array_key_exists('algorithm', $headerData)
            && in_array($headerData['algorithm'], array('MD5' /* SUPPORTED ALGORITHMS */))
        )
            ? $headerData['algorithm']
            : $this->defaultAlgorithm;

        if ($algorithm == 'MD5-sess') {
            /*
             * then A1 is calculated only once. This creates a 'session key' for
             * the authentication of subsequent requests and responses which is
             * different for each "authentication session", thus limiting the amount
             * of material hashed with any one key.
             */
            $ha1 = hash('md5', $ha1 . ':' . $headerData['nonce'] . ':' . $headerData['cnonce']);
        }

        // Calculate h(a2). The value of this hash depends on the qop
        // option selected by the client and the supported hash functions

        /*
        * The URI from Request-URI of the Request-Line; duplicated here
        * because proxies are allowed to change the Request-Line in transit.
        */
        if (isset($headerData['uri'])) {
            // Section 3.2.2.5 in RFC 2617 says the authenticating server must
            // verify that the URI field in the Authorization header is for the
            // same resource requested in the Request Line.
            $rUri = $this->request()->getTarget();
            $cUri = $headerData['uri'];

            // Section 3.2.2.5 seems to suggest that the value of the URI
            // Authorization field should be made into an absolute URI if the
            // Request URI is absolute, but it's vague, and that's a bunch of
            // code I don't want to write right now.

            // Make sure the path portion of both URIs is the same
            if (strtolower($rUri) != strtolower($cUri))
                return false;
        }

        switch ($headerData['qop']) {
            case 'auth':
                $a2 = $this->request()->getMethod() . ':' . $headerData['uri'];
                break;
            case 'auth-int':
                ## A2 = Method ":" digest-uri-value ":" H(entity-body)
            default:
                throw new \RuntimeException('Client requested an unsupported qop option');
        }


        // Using hash() should make parameterizing the hash algorithm
        // easier
        $ha2 = hash('md5', $a2);

        // Calculate the server's version of the request-digest. This must
        // match $data['response']. See RFC 2617, section 3.2.2.1
        $message = $headerData['nonce'] . ':' . $headerData['nc'] . ':' . $headerData['cnonce']
            . ':' . $headerData['qop'] . ':' . $ha2;

        $digest  = hash('md5', $ha1 . ':' . $message);

        // If Only our digest matches the client's let them in
        if ($digest !== $headerData['response'])
            return false;

        $identity = new IdentityUsername(array('username' => $headerData['username']));
        return $identity;
    }


    // Options:
    
    /**
     * Space-separated list of URIs that define the protection space.
     *
     * An absoluteURI in this list may refer to a different server
     * than the one being accessed.
     * If this directive is omitted or its value is empty, the client
     * should assume that the protection space consists of all URIs
     * on the responding server.
     *
     * @param string|array $domains
     * @return $this
     */
    function setDomains($domains)
    {
        if (is_array($domains))
            $domains = implode(' ', $domains);

        $this->domains = (string) $domains;
        return $this;
    }

    /**
     * Space-separated list of URIs that define the protection space
     *
     * @return string
     */
    function getDomains()
    {
        return $this->domains;
    }

    /**
     * Set Nonce Timeout
     *
     * @param int $timeout
     *
     * @return $this
     */
    function setNonceTimeout($timeout)
    {
        $this->nonceTimeout = (int) $timeout;
        return $this;
    }

    /**
     * Get Nonce Timeout
     * @return int
     */
    function getNonceTimeout()
    {
        return $this->nonceTimeout;
    }

    function setUseOpaque($flag = true)
    {
        $this->useOpaque = (boolean) $flag;
        return $this;
    }

    function isUseOpaque()
    {
        return $this->useOpaque;
    }


    // ...
    
    /**
     * Digest Header
     *
     * Generates a Proxy- or WWW-Authenticate header value in the Digest
     * authentication scheme.
     *
     * @return string Authenticate header value
     */
    protected function _getAuthenticateChallengeHeader()
    {
        $wwwauth = 'Digest realm="' . $this->getRealm() . '", '
            /*
             * Domain directive is not meaningful in Proxy-Authenticate headers,
             * for which the protection space is always the entire proxy; if present
             * it should be ignored.
             */
            . ( ($this->getDomains()) ? 'domain="' . $this->domains . '", ' : '' )
            . 'nonce="' . $this->_generateNonce() . '", '
            /*
             * This can be treated as a session id. If this changes the browser
             * will deauthenticate the user.
             */
            . ( ($this->isUseOpaque()) ? 'opaque="' . $this->_generateOpaque() . '", ' : '' )
            /*
             * indicating that the previous request from the client was
             * rejected because the nonce value was stale. If stale is TRUE
             * (case-insensitive), the client may wish to simply retry the request
             * with a new encrypted response, without reprompting the user for a
             * new username and password. The server should only set stale to TRUE
             * if it receives a request for which the nonce is invalid but with a
             * valid digest for that nonce (indicating that the client knows the
             * correct username/password). If stale is FALSE, or anything other
             * than TRUE, or the stale directive is not present, the username
             * and/or password are invalid, and new values must be obtained.
             */
            . ( (isset($this->stale)) ? 'stale="true"' : '' )
            . 'algorithm="' . $this->defaultAlgorithm . '", '
            . 'qop="' . implode(',', $this->supportedQops) . '"';

        return $wwwauth;
    }
    
    /**
     * Calculate Nonce
     *
     * server-specified quoted data string uniquely generated
     * each time a 401 response is made. It will be used for the
     * encryption of the username/password pair.
     *
     * server is free to construct the nonce such that it may only be used
     * from a particular client, for a particular resource, for a limited
     * period of time or number of uses, or any other restrictions
     *
     * @return string The nonce value
     */
    protected function _generateNonce()
    {
        /*
         * server would recalculate the hash portion after receiving the client
         * authentication header and reject the request if it did not match the
         * nonce from that header or if the time-stamp value is not recent enough.
         *
         * In this way the server can limit the time of the nonce's validity.
         */
        $timeout = ceil(time() / $this->nonceTimeout) * $this->nonceTimeout;

        /*
         * The inclusion of the ETag prevents a replay request for an updated
         * version of the resource.
         *
         * Note: including the IP address of the client in the nonce would appear
         * to offer the server the ability to limit the reuse of the nonce to the
         * same client that originally got it.
         * However, that would break proxy farms, where requests from a single
         * user often go through different proxies in the farm. Also, IP
         * address spoofing is not that hard.
         */

        $headers = $this->request()->headers();
        $Etag = null;
        if ($headers->has('Etag')) {
            $Etag = $this->request()->headers()->get('Etag')->current();
            $Etag = $Etag->renderValueLine();
        } elseif ($headers->has('User-Agent')) {
            $Etag = $headers->get('User-Agent')->current();
            $Etag = $Etag->renderValueLine();
        } elseif (isset($_SERVER['HTTP_USER_AGENT']))
            $Etag = $_SERVER['HTTP_USER_AGENT'];
        else
            $Etag = 'this_is_etag';

        $nonce = hash('md5', $timeout . ':' . $Etag . ':' . $this->nonce_secret);
        return $nonce;
    }

    /**
     * Calculate Opaque
     *
     * A string of data, specified by the server, which should be returned
     * by the client unchanged in the Authorization header of subsequent
     * requests with URIs in the same protection space.
     *
     * This can be treated as a session id. If this changes the browser
     * will deauthenticate the user.
     *
     * It is recommended that this string be base64 or hexadecimal data.
     *
     * It may be useful to store data in this string in some applications.
     *
     * @return string The opaque value
     */
    protected function _generateOpaque()
    {
        return base64_encode('opaque_data:');
    }
    
}
