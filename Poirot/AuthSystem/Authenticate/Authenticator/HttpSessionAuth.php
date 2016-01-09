<?php
namespace Poirot\AuthSystem\Authenticate\Authenticator;

use Poirot\AuthSystem\Authenticate\AbstractHttpAuthenticator;
use Poirot\Http\Header\HeaderFactory;
use Poirot\Http\Interfaces\iHeader;
use Poirot\Http\Util\cookie;
use Poirot\Http\Util\UCookie;
use Poirot\Storage\Gateway\SessionData;

class HttpSessionAuth extends AbstractHttpAuthenticator
{
    use TraitSessionAuth{
        TraitSessionAuth::signIn  as protected _t__signIn;
        TraitSessionAuth::signOut as protected _t__signOut;
    }

    /** @var string session id */
    protected $__session_id;

    /**
     * Login Authenticated User
     *
     * - Sign user in environment and server
     *   exp. store in session
     *
     * - logout current user if has
     *
     * @throws \Exception no identity defined
     * @return $this
     */
    function signIn()
    {
        session_regenerate_id(true);
        $this->__session_id = $sessionId = session_id();
        $this->response()->getHeaders()->set(HeaderFactory::factory(
            'Set-Cookie'
            , 'PHPSESSID='.$sessionId
              .'; path="/" '
              .'Expires: '. date('DD-Mon-YYYY HH:MM:SS GMT', time() + 2628000) // 5 years
        ));

        $this->_t__signIn();
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
        $this->response()->getHeaders()->set(HeaderFactory::factory(
            'Set-Cookie'
            , 'PHPSESSID=deleted'
            .'; path="/" Expires: Thu, 01-Jan-1970; 00:00:01; Max-Age=0;'
        ));

        $this->_t__signOut();
    }

    /**
     * Has User Logged in?
     *
     * - login mean that user identity signed with signIn method
     *   exp. Exists in Session or as a header in Request Http or etc..
     *
     * - validate sign
     *   ie. with token it must be exists and validate on server
     *
     * @return boolean
     */
    function isSignIn()
    {
        if($this->__session()->has(self::STORAGE_IDENTITY_KEY))
            return true;

        return false;
    }


    // ...

    /**
     * Get Session Storage
     * @return SessionData
     */
    function __session()
    {
        session_id($this->__getSessionID());

        if(!$this->_session)
            $this->_session = new SessionData(['realm' => $this->getRealm()]);

        return $this->_session;
    }

    function __getSessionID()
    {
        if ($this->__session_id)
            return $this->__session_id;

        /** @var iHeader $h */
        foreach($this->request->getHeaders() as $h) {
            if (strtolower($h->label()) != 'cookie')
                continue;

            $cookieVal = $h->renderValueLine();
            /** @var cookie $cookie */
            foreach(UCookie::parseCookie($cookieVal) as $cookie) {
                if ($cookie->name == 'PHPSESSID')
                    return $cookie->value;
            }
        }

        if (session_status() !== PHP_SESSION_ACTIVE)
            session_start();

        return $this->__session_id = session_id();

    }
}
