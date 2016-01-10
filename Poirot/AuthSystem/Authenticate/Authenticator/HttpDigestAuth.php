<?php
namespace Poirot\AuthSystem\Authenticate\Authenticator;

use Poirot\AuthSystem\Authenticate\AbstractHttpAuthenticator;
use Poirot\AuthSystem\Authenticate\Authenticator\Adapter\DigestFileAuthAdapter;
use Poirot\AuthSystem\Authenticate\Credential\UserPassCredential;
use Poirot\AuthSystem\Authenticate\Exceptions\AuthenticationException;
use Poirot\AuthSystem\Authenticate\Interfaces\iAuthAdapter;
use Poirot\AuthSystem\Authenticate\Interfaces\iCredential;
use Poirot\AuthSystem\Authenticate\Interfaces\iIdentity;
use Poirot\Http\Header\HeaderFactory;
use Poirot\Http\Message\HttpRequest;

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

class HttpDigestAuth extends AbstractHttpAuthenticator
{
    // Options
    /** @var bool */
    protected $proxyAuth          = false;
    protected $acceptBasicScheme  = true;
    protected $acceptDigestScheme = true;

    /** @var iAuthAdapter */
    protected $basicAdapter;

    ## digest options
    /** @var iAuthAdapter */
    protected $digestAdapter;
    protected $nonceTimeout = 30;
    /** @var string Space-delimited list of protected domains for Digest Auth */
    protected $domains = '192.168.123.161';
    /** @var string The actual algorithm to use. Defaults to MD5 */
    protected $algo = 'MD5';
    /**
     * List of supported qop options. My intention is to support both 'auth' and
     * 'auth-int', but 'auth-int' won't make it into the first version.
     */
    protected $supportedQops = ['auth'];
    protected $useOpaque = false;

    /**
     * Do Extract Credential From Request Object
     * ie. post form data or token
     *
     * @param HttpRequest $request
     *
     * @return iCredential|iAuthAdapter|null Null if not available
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
            $credential = $this->__extractBasicCredential($hValue);
        else
            $credential = $this->__extractDigestCredential($hValue);

        return $credential;
    }

        protected function __extractBasicCredential($hValue)
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

            $credential = new UserPassCredential(['username' => $creds[0], 'password' => $creds[1]]);
            return $credential;
        }

        protected function __extractDigestCredential($hValue)
        {
            $headerData = $this->_parseDigestAuth($hValue);
            if ($headerData === false)
                return false;

            // Verify that the client sent back the same nonce
            if ($this->_calcNonce() != $headerData['nonce'])
                return false;

            // The opaque value is also required to match, but of course IE doesn't
            // play ball.
            if (!$this->ieNoOpaque && $this->_calcOpaque() != $headerData['opaque'])
                return false;


            // ...

            // Look up the user's password hash. If not found, deny access.
            // This makes no assumptions about how the password hash was
            // constructed beyond that it must have been built in such a way as
            // to be recreatable with the current settings of this object.
            $ha1 = $this->digestResolver->resolve($data['username'], $data['realm']);
            if ($ha1 === false) {
                return $this->_challengeClient();
            }

            // If MD5-sess is used, a1 value is made of the user's password
            // hash with the server and client nonce appended, separated by
            // colons.
            if ($this->algo == 'MD5-sess') {
                $ha1 = hash('md5', $ha1 . ':' . $data['nonce'] . ':' . $data['cnonce']);
            }

            // Calculate h(a2). The value of this hash depends on the qop
            // option selected by the client and the supported hash functions
            switch ($data['qop']) {
                case 'auth':
                    $a2 = $this->request->getMethod() . ':' . $data['uri'];
                    break;
                case 'auth-int':
                    // Should be REQUEST_METHOD . ':' . uri . ':' . hash(entity-body),
                    // but this isn't supported yet, so fall through to default case
                default:
                    throw new Exception\RuntimeException('Client requested an unsupported qop option');
            }
            // Using hash() should make parameterizing the hash algorithm
            // easier
            $ha2 = hash('md5', $a2);


            // Calculate the server's version of the request-digest. This must
            // match $data['response']. See RFC 2617, section 3.2.2.1
            $message = $data['nonce'] . ':' . $data['nc'] . ':' . $data['cnonce'] . ':' . $data['qop'] . ':' . $ha2;
            $digest  = hash('md5', $ha1 . ':' . $message);

            // If our digest matches the client's let them in, otherwise return
            // a 401 code and exit to prevent access to the protected resource.
            if (CryptUtils::compareStrings($digest, $data['response'])) {
                $identity = array('username' => $data['username'], 'realm' => $data['realm']);
                return new Authentication\Result(Authentication\Result::SUCCESS, $identity);
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
    function attainSignedIdentity()
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
        $this->__sendAuthorizationHeaders();
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
     * @param AuthenticationException $exception
     *
     * @throws AuthenticationException
     */
    protected function riseException(AuthenticationException $exception)
    {
        $this->__sendAuthorizationHeaders();

        $exception->setAuthenticator($this);
        throw $exception;
    }

        protected function __sendAuthorizationHeaders()
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
     * @return iAuthAdapter
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
     * @return iAuthAdapter
     */
    function getDigestAdapter()
    {
        if (!$this->digestAdapter)
            $this->setDigestAdapter(new DigestFileAuthAdapter);

        return $this->digestAdapter;
    }

    /**
     * Get Basic Adapter
     * @return iAuthAdapter
     */
    function getBasicAdapter()
    {
        if (!$this->basicAdapter)
            $this->setBasicAdapter(new DigestFileAuthAdapter);

        return $this->basicAdapter;
    }

    /**
     * Set Digest Adapter
     * @param iAuthAdapter $adapter
     * @return $this
     */
    function setDigestAdapter(iAuthAdapter $adapter)
    {
        $this->digestAdapter = $adapter;
        return $this;
    }

    /**
     * Set Basic Adapter
     * @param iAuthAdapter $adapter
     * @return $this
     */
    function setBasicAdapter(iAuthAdapter $adapter)
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
        return (!$this->isAcceptDigest()) && $this->acceptBasicScheme;
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
            . 'domain="' . $this->domains . '", '
            . 'nonce="' . $this->_calcNonce() . '", '
            . ($this->isUseOpaque() ? 'opaque="' . $this->_calcOpaque() . '", ' : '')
            . 'algorithm="' . $this->algo . '", '
            . 'qop="' . implode(',', $this->supportedQops) . '"';

        return $wwwauth;
    }

    /**
     * Calculate Nonce
     *
     * server-specified quoted data string uniquely generated
     * each time a 401 response is made. It will be used for the
     * encryption of the username/password pair
     *
     * @return string The nonce value
     */
    protected function _calcNonce()
    {
        // Once subtle consequence of this timeout calculation is that it
        // actually divides all of time into nonceTimeout-sized sections, such
        // that the value of timeout is the point in time of the next
        // approaching "boundary" of a section. This allows the server to
        // consistently generate the same timeout (and hence the same nonce
        // value) across requests, but only as long as one of those
        // "boundaries" is not crossed between requests. If that happens, the
        // nonce will change on its own, and effectively log the user out. This
        // would be surprising if the user just logged in.
        $timeout = ceil(time() / $this->nonceTimeout) * $this->nonceTimeout;

        $userAgentHeader = $this->request->getHeaders()->get('User-Agent');
        if ($userAgentHeader)
            $userAgent = $userAgentHeader->renderValueLine();
        elseif (isset($_SERVER['HTTP_USER_AGENT']))
            $userAgent = $_SERVER['HTTP_USER_AGENT'];
        else
            $userAgent = self::STORAGE_IDENTITY_KEY;

        $nonce = hash('md5', $timeout . ':' . $userAgent . ':' . __CLASS__);
        return $nonce;
    }

    /**
     * Calculate Opaque
     *
     * This field is optional.
     *
     * quoted data string replied unchanged the whole session by the client;
     * it might be used for example for session tracking by the web server.
     *
     * The opaque string can be anything; the client must return it exactly as
     * it was sent. It may be useful to store data in this string in some
     * applications. Ideally, a new value for this would be generated each time
     * a WWW-Authenticate header is sent (in order to reduce predictability),
     * but we would have to be able to create the same exact value across at
     * least two separate requests from the same client.
     *
     * @return string The opaque value
     */
    protected function _calcOpaque()
    {
        return hash('md5', 'Opaque Data:' . __CLASS__);
    }


    /**
     * Parse Digest Authorization header
     *
     * @param  string $header Client's Authorization: HTTP header
     * @return array|bool Data elements from header, or false if any part of
     *                    the header is invalid
     */
    protected function _parseDigestAuth($header)
    {
        $temp = null;
        $data = [];

        ## username ------------------------------------------------------
        $ret = preg_match('/username="([^"]+)"/', $header, $temp);
        if (!$ret || empty($temp[1])
            || !ctype_print($temp[1])
            || strpos($temp[1], ':') !== false
        )
            return false;
        else
            $data['username'] = $temp[1];


        ## realm ----------------------------------------------------------
        $temp = null;
        $ret = preg_match('/realm="([^"]+)"/', $header, $temp);
        if (!$ret || empty($temp[1]))
            return false;

        if (!ctype_print($temp[1]) || strpos($temp[1], ':') !== false)
            return false;
        else
            $data['realm'] = $temp[1];

        ## nonce ---------------------------------------------------------
        $temp = null;
        $ret = preg_match('/nonce="([^"]+)"/', $header, $temp);
        if (!$ret || empty($temp[1]))
            return false;
        if (!ctype_xdigit($temp[1]))
            return false;

        $data['nonce'] = $temp[1];

        ## uri -----------------------------------------------------------
        $temp = null;
        $ret = preg_match('/uri="([^"]+)"/', $header, $temp);
        if (!$ret || empty($temp[1]))
            return false;

        // Section 3.2.2.5 in RFC 2617 says the authenticating server must
        // verify that the URI field in the Authorization header is for the
        // same resource requested in the Request Line.
        $rUri = $this->request->getUri();
        $cUri = $temp[1];

        // Make sure the path portion of both URIs is the same
        if ($rUri->getPath()->toString() != strtolower($cUri))
            return false;

        // Section 3.2.2.5 seems to suggest that the value of the URI
        // Authorization field should be made into an absolute URI if the
        // Request URI is absolute, but it's vague, and that's a bunch of
        // code I don't want to write right now.
        $data['uri'] = $temp[1];

        ## reponse -------------------------------------------------------
        $temp = null;
        $ret = preg_match('/response="([^"]+)"/', $header, $temp);
        if (!$ret || empty($temp[1]))
            return false;

        if (32 != strlen($temp[1]) || !ctype_xdigit($temp[1]))
            return false;

        $data['response'] = $temp[1];

        ## algorithm -------------------------------------------------------------
        $temp = null;
        // The spec says this should default to MD5 if omitted. OK, so how does
        // that square with the algo we send out in the WWW-Authenticate header,
        // if it can easily be overridden by the client?
        $ret = preg_match('/algorithm="?(' . $this->algo . ')"?/', $header, $temp);
        if ($ret && !empty($temp[1])
            && in_array($temp[1], ['MD5' /* SUPPORTED ALGORITHMS */]))
            $data['algorithm'] = $temp[1];
        else
            $data['algorithm'] = 'MD5';  // = $this->algo; ?


        ## cnonce -----------------------------------------------------------------
        $temp = null;
        // Not optional in this implementation
        $ret = preg_match('/cnonce="([^"]+)"/', $header, $temp);
        if (!$ret || empty($temp[1]))
            return false;
        if (!ctype_print($temp[1]))
            return false;

        $data['cnonce'] = $temp[1];

        ## opaque -----------------------------------------------------------------
        $temp = null;
        // If the server sent an opaque value, the client must send it back
        if ($this->isUseOpaque()) {
            $ret = preg_match('/opaque="([^"]+)"/', $header, $temp);
            if (!$ret || empty($temp[1])) {

                // Big surprise: IE isn't RFC 2617-compliant.
                $headers = $this->request->getHeaders();
                if (!$headers->has('User-Agent'))
                    return false;

                $userAgent = $headers->get('User-Agent')->renderValueLine();
                if (false === strpos($userAgent, 'MSIE'))
                    return false;

                $temp[1] = '';
                $this->ieNoOpaque = true;
            }

            // This implementation only sends MD5 hex strings in the opaque value
            if (!$this->ieNoOpaque &&
                (32 != strlen($temp[1]) || !ctype_xdigit($temp[1])))
                return false;

            $data['opaque'] = $temp[1];
        }

        ## qop ---------------------------------------------------------------------------------------
        // Not optional in this implementation, but must be one of the supported
        // qop types
        $temp = null;
        $ret = preg_match('/qop="?(' . implode('|', $this->supportedQops) . ')"?/', $header, $temp);
        if (!$ret || empty($temp[1]))
            return false;

        if (!in_array($temp[1], $this->supportedQops))
            return false;

        $data['qop'] = $temp[1];

        ## nc ---------------------------------------------------------------------------------------
        // Not optional in this implementation. The spec says this value
        // shouldn't be a quoted string, but apparently some implementations
        // quote it anyway. See ZF-1544.
        $temp = null;
        $ret = preg_match('/nc="?([0-9A-Fa-f]{8})"?/', $header, $temp);
        if (!$ret || empty($temp[1]))
            return false;

        if (8 != strlen($temp[1]) || !ctype_xdigit($temp[1]))
            return false;

        $data['nc'] = $temp[1];


        return $data;
    }
}
