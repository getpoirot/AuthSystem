<?php
namespace Poirot\AuthSystem\Authenticate\Identifier;

use Poirot\AuthSystem\Authenticate\Interfaces\iIdentity;
use Poirot\Storage\Gateway\DataStorageSession;

class IdentifierSession 
    extends aIdentifier
{
    protected $_session;
    
    /**
     * Attain Identity Object From Signed Sign
     * exp. session, extract from authorize header,
     *      load lazy data, etc.
     *
     * !! call when user is signed in to retrieve user identity
     *
     * note: almost retrieve identity data from cache or
     *       storage that store user data. ie. session
     *
     * @see identity()
     * @return iIdentity|\Traversable|null Null if no change need
     */
    function doIdentifierSignedIdentity()
    {
        $identity = $this->_storage()->get(self::STORAGE_IDENTITY_KEY);
        return $identity;
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
        if (!($identity = $this->identity) && !$identity->isFulfilled())
            throw new \Exception('Identity not exists or not fullfilled');

        $this->_storage()->set(self::STORAGE_IDENTITY_KEY , $identity);
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
        $this->_storage()->destroy();
        $this->identity()->clean();
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
        if($this->_storage()->has(self::STORAGE_IDENTITY_KEY))
            return true;

        return false;
    }
    
    
    // ..

    /**
     * Get Session Storage
     * @return DataStorageSession
     */
    function _storage()
    {
        if(!$this->_session) {
            $session = new DataStorageSession();
            $session->setRealm($this->getRealm());
            $this->_session = $session;
        }

        return $this->_session;
    }
}
