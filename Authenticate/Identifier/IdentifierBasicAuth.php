<?php
namespace Poirot\AuthSystem\Authenticate\Identifier;

use Poirot\AuthSystem\Authenticate\Identity\IdentityUsername;
use Poirot\AuthSystem\Authenticate\Interfaces\iIdentityCredentialRepo;
use Poirot\AuthSystem\Authenticate\Interfaces\iIdentity;
use Poirot\AuthSystem\Authenticate\Identifier\HttpDigest;

/*
$adapter = new P\AuthSystem\Authenticate\RepoIdentityCredential\IdentityCredentialDigestFile();
$authenticator = new P\AuthSystem\Authenticate\Authenticator(
    new P\AuthSystem\Authenticate\Identifier\IdentifierBasicAuth('realm_members', [
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
    # $authenticator->identifier()->signOut();

} catch (P\AuthSystem\Authenticate\Exceptions\exAuthentication $e)
{
    $e->issueException();
}
*/

class IdentifierBasicAuth
    extends aIdentifier
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
        $r = isset($_SERVER['PHP_AUTH_USER']) && isset($_SERVER['PHP_AUTH_PW']);
        return ($r !== false);
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
     * @return null|iIdentity|\Traversable Null if no change need
     * @throws \Exception
     */
    protected function doRecognizedIdentity()
    {
        $UserPass = array('username'=>$_SERVER['PHP_AUTH_USER'], 'password'=>$_SERVER['PHP_AUTH_PW']);

        $credentialAdapter = $this->credentialAdapter;
        if (!$credentialAdapter)
            throw new \Exception('Credential Adapter Repository not defined.');

        $credentialAdapter = clone $credentialAdapter;
        $credentialAdapter->setRealm($this->getRealm());
        $credentialAdapter->import($UserPass); # [ username=>xx, password=>xx ]
        return $credentialAdapter->findIdentityMatch();
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
        throw new \Exception('SignIn Method for Http Authentication Basic can`t implemented by mean.');
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
        // Credential Repo Cause To Achieve Valid Unique Username
        return new IdentityUsername();
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
        header($headerName.':'.$this->_getAuthenticateChallengeHeader());
        header("HTTP/1.0 {$statusCode} Unauthorized");
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
