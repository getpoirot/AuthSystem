<?php
namespace Poirot\AuthSystem\Authenticate\Identifier;

use Poirot\AuthSystem\Authenticate\Interfaces\iIdentityCredentialRepo;
use Poirot\AuthSystem\Authenticate\Interfaces\iIdentity;
use Poirot\Http\Header\FactoryHttpHeader;

use \Poirot\AuthSystem\Authenticate\Identifier\HttpDigest;

class IdentifierHttpBasicAuth
    extends aIdentifierHttp
{
    // Options
    /** @var bool */
    protected $proxyAuth = false;
    /** @var iIdentityCredentialRepo */
    protected $credentialAdapter;

    
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
     * @see withIdentity()
     * @return iIdentity|\Traversable|null Null if no change need
     */
    protected function doRecognizedIdentity()
    {
        // TODO: Implement doRecognizedIdentity() method.
    }

    /**
     * Default Exception Issuer
     * @return \Closure
     */
    protected function doIssueExceptionDefault()
    {
        $self = $this;
        return function($e) use ($self) {
            $self->_setChallengeHeaders();
        };
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
        // TODO: Implement signIn() method.
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
        $this->_setChallengeHeaders();
    }

    /**
     * Get Default Identity Instance
     * that Signed data load into
     *
     * @return iIdentity
     */
    protected function _newDefaultIdentity()
    {
        // TODO: Implement _newDefaultIdentity() method.
    }
    
    
    // Options:

    /**
     * Set Basic Adapter
     * @param iIdentityCredentialRepo $adapter
     * @return $this
     */
    function setCredentialAdapter(iIdentityCredentialRepo $adapter)
    {
        $this->credentialAdapter = $adapter;
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

    
    // ...

    /**
     * Manipulate Response Object Headers To Challenge User
     * To Login With Display The User/Pass Window
     *
     */
    protected function _setChallengeHeaders()
    {
        if ($this->isProxyAuth()) {
            $statusCode = 407;
            $headerName = 'Proxy-Authenticate';
        } else {
            $statusCode = 401;
            $headerName = 'WWW-Authenticate';
        }

        // Send a challenge in each acceptable authentication scheme
        $this->response()->setStatusCode($statusCode);

        $headers = $this->response()->headers();
        $headers->insert(FactoryHttpHeader::of(array(
                $headerName => $this->_getAuthenticateChallengeHeader())
        ));

        // $headers->insert(FactoryHttpHeader::of( array('Authorization' => 'deleted')) );
    }

    /**
     * Basic Header
     *
     * Generates a Proxy- or WWW-Authenticate header value in the Basic
     * authentication scheme.
     *
     * @return string Authenticate header value
     */
    protected function _getAuthenticateChallengeHeader()
    {
        return 'Basic realm="' . $this->getRealm() . '"';
    }
}
