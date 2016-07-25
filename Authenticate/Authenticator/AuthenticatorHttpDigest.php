<?php
namespace Poirot\AuthSystem\Authenticate\Authenticator;

use Poirot\AuthSystem\Authenticate\aAuthenticatorHttp;
use Poirot\AuthSystem\Authenticate\Authenticator\Adapter\AuthAdapterDigestFile;
use Poirot\AuthSystem\Authenticate\Credential\CredentialOpen;
use Poirot\AuthSystem\Authenticate\Credential\CredentialUserPass;
use Poirot\AuthSystem\Authenticate\Exceptions\exAuthentication;
use Poirot\AuthSystem\Authenticate\Identity\IdentityHttpDigest;
use Poirot\AuthSystem\Authenticate\Identity\IdentityUsername;
use Poirot\AuthSystem\Authenticate\Interfaces\iIdentityCredentialRepo;
use Poirot\AuthSystem\Authenticate\Interfaces\iCredential;
use Poirot\AuthSystem\Authenticate\Interfaces\iIdentity;

/*
$request  = new HttpRequest(new PhpServerRequestBuilder);
$response = new HttpResponse(new PhpServerResponseBuilder);

$lazyLoad = new LazyFulfillmentIdentity(['fulfillment_by' => 'username', 'data_provider' => new UserData]);

$auth     = new Authenticator\HttpDigestAuth([
    'identity' => $lazyLoad,
    'request'  => $request,
    'response' => $response,
    'accept_digest' => false,
]);

try {
    $credential = null;

    ## check user has authenticated
    $auth->authenticate($credential);

} catch (WrongCredentialException $e) {
    throw new \Exception('Invalid Username or Password.');
} catch (UserNotFoundException $e) {
    throw new \Exception('Invalid Username or Password.');
} catch (AuthenticationException $e)
{
    $e->getAuthenticator()->response()->flush();
    echo $e->getMessage();
    die();
}

## run rest of program
if ($auth->hasAuthenticated()) {
    $response->setBody("<h1>Hello User {$auth->identity()->getEmail()}</h1>");
}

### send response
$response->flush();
*/

class AuthenticatorHttpDigest
    extends aAuthenticatorHttp
{
    // Options
    /** @var bool */
    protected $proxyAuth          = false;
    protected $acceptBasicScheme  = true;
    protected $acceptDigestScheme = true;

    /** @var iIdentityCredentialRepo */
    protected $basicAdapter;

    ## digest options
    /** @var iIdentityCredentialRepo */
    protected $digestAdapter;

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
    protected $supportedQops = ['auth'];
    protected $useOpaque     = true;


    /**
     * Do Extract Credential From Request Object
     * ie. post form data or token
     *
     * @param HttpRequest $request
     *
     * @return iCredential|iIdentityCredentialRepo|iIdentity|null Null if not available
     */
    function doExtractCredentialFromRequest(HttpRequest $request)
    {
        if ($this->isProxyAuth())
            $headerName = 'Proxy-Authorization';
        else
            $headerName = 'Authorization';

        $headers = $request->getHeaders();
        if (!($headers->has($headerName) && $hValue = $headers->get($headerName)->renderValueLine()))
            ## Authorization Header Not Found. exception will rise contains header to challenge user for login
            return null;


        // ...

        list($clientScheme) = explode(' ', trim($hValue));
        $clientScheme       = strtolower($clientScheme);

        if (!in_array($clientScheme, ['basic', 'digest']))
            ## not support, Authorization: basic .....
            return null;

        ## scheme not acceptable by config
        if ($clientScheme == 'digest' && !$this->isAcceptDigest())
            return null;
        if ($clientScheme == 'basic'  && !$this->isAcceptBasic())
            return null;


        if ($clientScheme == 'basic')
            $credential = $this->__computeBasicCredential($hValue);
        else
            $credential = $this->__computeDigestCredential($hValue);

        return $credential;
    }

        protected function __computeBasicCredential($hValue)
        {
            // Decode the Authorization header
            $auth = substr($hValue, strlen('Basic '));
            $auth = base64_decode($auth);
            if (!$auth)
                throw new \RuntimeException('Unable to base64_decode Authorization header value');

            # it may be empty or invalid
            if (!ctype_print($auth))
                return false;
            $creds = array_filter(explode(':', $auth));
            if (count($creds) != 2)
                return false;

            $credential = new CredentialUserPass(['username' => $creds[0], 'password' => $creds[1]]);
            return $credential;
        }

        protected function __computeDigestCredential($hValue)
        {
            /* TODO
             * If a directive or its value is improper, or required directives are
             * missing, the proper response is 400 Bad Request. If the request-
             * digest is invalid, then a login failure should be logged, since
             * repeated login failures from a single client may indicate an attacker
             * attempting to guess passwords.
             */
            $headerData = $this->_parseDigestRequestHeader($hValue);
            if ($headerData === false)
                return false;


            if ($this->__generateNonce() != $headerData['nonce'])
                ## client sent back same nonce
                return false;


            // If the server sent an opaque value, the client must send it back
            if ($this->isUseOpaque()) {
                // Validate Opaque
                if (!isset($headerData['opaque']))
                    return false;
                elseif ($this->__generateOpaque() != $headerData['opaque'])
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
            $digestIdentity = $this->getDigestAdapter()->findIdentityMatch(
                new CredentialOpen(['username' => $headerData['username']])
            );

            $ha1 = $digestIdentity->getA1();

            $algorithm = (
                array_key_exists('algorithm', $headerData)
                && in_array($headerData['algorithm'], ['MD5' /* SUPPORTED ALGORITHMS */])
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
                $rUri = $this->request->getUri();
                $cUri = $headerData['uri'];

                // Section 3.2.2.5 seems to suggest that the value of the URI
                // Authorization field should be made into an absolute URI if the
                // Request URI is absolute, but it's vague, and that's a bunch of
                // code I don't want to write right now.

                // Make sure the path portion of both URIs is the same
                if ($rUri->getPath()->toString() != strtolower($cUri))
                    return false;
            }

            switch ($headerData['qop']) {
                case 'auth':
                    $a2 = $this->request->getMethod() . ':' . $headerData['uri'];
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
            $message = $headerData['nonce'] . ':' . $headerData['nc'] . ':' . $headerData['cnonce'] . ':' . $headerData['qop'] . ':' . $ha2;
            $digest  = hash('md5', $ha1 . ':' . $message);

            // If our digest matches the client's let them in
            if ($digest == $headerData['response']) {
                $identity = new IdentityUsername([ 'username' => $headerData['username'] ]);
                return $identity;
            }
        }

    /**
     * Attain Identity Object From Signed Sign
     *
     * !! call when user is signed in to retrieve user identity
     *
     * note: almost retrieve identity data from cache or
     *       storage that store user data. ie. session
     *
     * @see identity()
     * @return iIdentity|null Null if no change need
     */
    function doIdentifierSignedIdentity()
    {
        ## when user signed in, identity is available during authentication process with
        ## Authorize header and no need to change.
        return null;
    }

    /**
     * Login Authenticated User
     *
     * - Sign user in environment and server
     *   exp. store in session, store data in cache
     *        sign user token in header, etc.
     *
     * - logout current user if has
     *
     * @throws \Exception no identity defined
     * @return $this
     */
    function signIn()
    {
        ## Authorize header added by client(browser) and sent again on each request
        ## so nothing more with signIn
        return $this;
    }

    /**
     * Logout Authenticated User
     *
     * - it must destroy sign
     *   ie. destroy session or invalidate token in storage
     *
     * - clear identity
     *
     * @return void
     */
    function signOut()
    {
        $this->__sendChalengeHeaders();
    }

    /**
     * Has User Logged in?
     *
     * - login mean that user uid exists in the storage
     *
     * note: never check remember flag
     *   the user that authenticated with
     *   Remember Me must recognized when
     *   exists.
     *
     * note: user must be login() to recognize here
     *
     * @return boolean
     */
    function isSignIn()
    {
        return $this->request->getHeaders()->has('Authorization');
    }

    /**
     * Manipulate Response From Exception Then Throw It
     *
     * @param exAuthentication $exception
     *
     * @throws exAuthentication
     */
    protected function riseException(exAuthentication $exception)
    {
        $this->__sendChalengeHeaders();

        $exception->setAuthenticator($this);
        throw $exception;
    }

        protected function __sendChalengeHeaders()
        {
            if ($this->isProxyAuth()) {
                $statusCode = 407;
                $headerName = 'Proxy-Authenticate';
            } else {
                $statusCode = 401;
                $headerName = 'WWW-Authenticate';
            }

            // Send a challenge in each acceptable authentication scheme
            $this->response()->setStatCode($statusCode);

            $headers = $this->response()->getHeaders();
            if ($this->isAcceptBasic())
                $headers->set(HeaderFactory::factory($headerName, $this->_getBasicHeader()));

            if ($this->isAcceptDigest())
                $headers->set(HeaderFactory::factory($headerName, $this->_getDigestHeader()));

            // $headers->set(HeaderFactory::factory('Authorization', 'deleted'));
        }


    // Options:

    /**
     * Get Authentication Adapter
     *
     * @return iIdentityCredentialRepo
     */
    function getAdapter()
    {
        $adapter = $this->getBasicAdapter();

        if ($this->isAcceptDigest())
            $adapter = $this->getDigestAdapter();

        $adapter->setRealm($this->getRealm());
        return $adapter;
    }

    /**
     * Get Digest Adapter
     * @return iIdentityCredentialRepo
     */
    function getDigestAdapter()
    {
        if (!$this->digestAdapter)
            $this->setDigestAdapter(new AuthAdapterDigestFile);

        return $this->digestAdapter;
    }

    /**
     * Get Basic Adapter
     * @return iIdentityCredentialRepo
     */
    function getBasicAdapter()
    {
        if (!$this->basicAdapter)
            $this->setBasicAdapter(new AuthAdapterDigestFile);

        return $this->basicAdapter;
    }

    /**
     * Set Digest Adapter
     * @param iIdentityCredentialRepo $adapter
     * @return $this
     */
    function setDigestAdapter(iIdentityCredentialRepo $adapter)
    {
        $this->digestAdapter = $adapter;
        return $this;
    }

    /**
     * Set Basic Adapter
     * @param iIdentityCredentialRepo $adapter
     * @return $this
     */
    function setBasicAdapter(iIdentityCredentialRepo $adapter)
    {
        $this->basicAdapter = $adapter;
        return $this;
    }


    /**
     * Whether or not to do Proxy Authentication instead of origin server
     * authentication (send 407's instead of 401's). Off by default.
     *
     * @param bool|true $flag
     * @return $this
     */
    function setProxyAuth($flag = true)
    {
        $this->proxyAuth = (boolean) $flag;
        return $this;
    }

    /**
     * Using Proxy Authentication?
     * @return boolean
     */
    function isProxyAuth()
    {
        return $this->proxyAuth;
    }

    function setAcceptBasic($flag = true)
    {
        $this->acceptBasicScheme = (boolean) $flag;
        return $this;
    }

    function isAcceptBasic()
    {
        ## !! when we accept digest, basic authentication will not acceptable both.
        return $this->acceptBasicScheme;
    }

    function setAcceptDigest($flag = true)
    {
        $this->acceptDigestScheme = (boolean) $flag;
        return $this;
    }

    function isAcceptDigest()
    {
        return $this->acceptDigestScheme;
    }

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
     * Basic Header
     *
     * Generates a Proxy- or WWW-Authenticate header value in the Basic
     * authentication scheme.
     *
     * @return string Authenticate header value
     */
    protected function _getBasicHeader()
    {
        return 'Basic realm="' . $this->getRealm() . '"';
    }

    /**
     * Digest Header
     *
     * Generates a Proxy- or WWW-Authenticate header value in the Digest
     * authentication scheme.
     *
     * @return string Authenticate header value
     */
    protected function _getDigestHeader()
    {
        $wwwauth = 'Digest realm="' . $this->getRealm() . '", '
            /*
             * Domain directive is not meaningful in Proxy-Authenticate headers,
             * for which the protection space is always the entire proxy; if present
             * it should be ignored.
             */
            . ( ($this->getDomains()) ? 'domain="' . $this->domains . '", ' : '' )
            . 'nonce="' . $this->__generateNonce() . '", '
            /*
             * This can be treated as a session id. If this changes the browser
             * will deauthenticate the user.
             */
            . ( ($this->isUseOpaque()) ? 'opaque="' . $this->__generateOpaque() . '", ' : '' )
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
    protected function __generateNonce()
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

        $Etag = null;
        if ($this->request->getHeaders()->has('Etag'))
            $Etag = $this->request->getHeaders()->get('Etag')->renderValueLine();
        elseif ($this->request->getHeaders()->has('User-Agent'))
            $Etag = $this->request->getHeaders()->get('User-Agent')->renderValueLine();
        elseif (isset($_SERVER['HTTP_USER_AGENT']))
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
    protected function __generateOpaque()
    {
        return base64_encode('opaque_data:');
    }


    /**
     * Parse Digest Authorization header
     *
     * credentials = "Digest" digest-response
     * digest-response = 1#( username | realm | nonce | digest-uri
     *      | response | [ algorithm ] | [cnonce] | [opaque]
     *      | [message-qop] | [nonce-count] | [auth-param] )
     *
     * @param  string $header Client's Authorization: HTTP header
     * @return array|bool Data elements from header, or false if any part of
     *                    the header is invalid
     */
    protected function _parseDigestRequestHeader($header)
    {
        preg_match_all('@(\w+)=(?:(?:")([^"]+)"|([^\s,$]+))@', $header, $matches, PREG_SET_ORDER);

        $data = [];
        foreach ($matches as $m) {
            $key   = $m[1];
            $value = ($m[2]) ? $m[2] : $m[3];

            switch ($key) {
                case 'realm':
                case 'username': if (!ctype_print($value)) return false;
                    break;
                case 'nonce': if (!ctype_xdigit($value)) return false;
                    break;
                /*
                * A string of 32 hex digits computed as defined below, which proves
                * that the user knows a password
                */
                case 'response': if (32 != strlen($value) || !ctype_xdigit($value)) return false;
                    break;
                /*
                 * Indicates what "quality of protection" the client has applied to
                 * the message. If present, its value MUST be one of the alternatives
                 * the server indicated it supports in the WWW-Authenticate header.
                 */
                case 'qop':
                    if (!in_array($value, $this->supportedQops))
                        ## TODO not support challenge again with alternative if exists
                        return false;
                    break;
                /*
                 * This MUST be specified if a qop directive is sent (see above), and
                 * MUST NOT be specified if the server did not send a qop directive in
                 * the WWW-Authenticate header field. The nc-value is the hexadecimal
                 * count of the number of requests (including the current request)
                 * that the client has sent with the nonce value in this request. For
                 * example, in the first request sent in response to a given nonce
                 * value, the client sends "nc=00000001". The purpose of this
                 * directive is to allow the server to detect request replays by
                 * maintaining its own copy of this count - if the same nc-value is
                 * seen twice, then the request is a replay.
                 */
                case 'nc': if (8 != strlen($value) || !ctype_xdigit($value)) return false;
                    break;
            }

            $data[$key] = $value;
        }

        return $data;

        ## cnonce -----------------------------------------------------------------
        /*
         * Nonce-count. This a hexadecimal serial number for the request.
         * The client should increase this number by one for every request.
         *
         * This MUST be specified if a qop directive is sent (see above), and
         * MUST NOT be specified if the server did not send a qop directive in
         * the WWW-Authenticate header field. The cnonce-value is an opaque
         * quoted string value provided by the client and used by both client
         * and server to avoid chosen plaintext attacks, to provide mutual
         * authentication, and to provide some message integrity protection.
         */
    }
}
