<?php

namespace Poirot\AuthSystem\Authenticate;

use Poirot\AuthSystem\Authenticate\Interfaces\iIdentity;
use Poirot\Storage\Gateway\SessionData;

class PhpHttpIdentifier extends AbstractIdentifier
{
    protected $_session;
    protected $_cookie;

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
        if (!($identity = $this->identity) && !$identity->isFulfilled())
            throw new \Exception('Identity not exists or not fullfilled');

        $this->__session()->set(self::STORAGE_IDENTITY_KEY , $identity);
        return $this;
    }

    /**
     * Attain Identity Object From Signed Sign
     * @return iIdentity
     */
    function attainSignedIdentity()
    {
        $defaultIdentity = $this->getDefaultIdentity();
        if ($this->__session()->has(self::STORAGE_IDENTITY_KEY))
            $defaultIdentity->from($this->__session()->get(self::STORAGE_IDENTITY_KEY));

        return $defaultIdentity;
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
        $this->identity()->clean();
        $this->__session()->destroy();
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
        if(!$this->_session)
            $this->_session = new SessionData(['realm' => $this->getRealm()]);

        return $this->_session;
    }
}
