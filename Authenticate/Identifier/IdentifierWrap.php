<?php
namespace Poirot\AuthSystem\Authenticate\Identifier;

use Poirot\AuthSystem\Authenticate\Interfaces\iIdentifier;
use Poirot\AuthSystem\Authenticate\Interfaces\iIdentity;

class IdentifierWrap 
    implements iIdentifier
{
    /** @var iIdentifier */
    protected $identifier;

    
    /**
     * IdentifierWrapIdentityMap constructor.
     * 
     * @param iIdentifier $identifier Wrapped Identifier
     */
    function __construct(iIdentifier $identifier)
    {
        $this->identifier = $identifier;
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
        $this->identifier->identity()->import($this->identity());
        $this->identifier->signIn();
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
        $this->identifier->signOut();
        $this->identity()->clean();
    }

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
        return $this->identifier->canRecognizeIdentity();
    }

    /**
     * Set Realm To Limit Authentication
     *
     * ! mostly used as storage namespace to have
     *   multiple area for each different Authenticate system
     *
     * @param string $realm
     *
     * @return $this
     */
    function setRealm($realm)
    {
        $this->identifier->setRealm($realm);
        return $this;
    }

    /**
     * Get Realm Area
     *
     * @return string
     */
    function getRealm()
    {
        return $this->identifier->getRealm();
    }

    /**
     * Get Authenticated User Data
     *
     * - for check that user is signIn the identity must
     *   fulfilled.
     * - if canRecognizeIdentity extract data from it
     *   this cause identity fulfillment with given data
     *   ie. when user exists in session build identity from that
     *
     * @return iIdentity
     */
    function identity()
    {
        return $this->identifier->identity();
    }

    // ..
    
    function __call($name, $arguments)
    {
        $r = call_user_func_array(array($this->identifier, $name), $arguments);
        if ($r instanceof $this->identifier)
            // when identifier return self instance we proxy it again to wrapper
            $r = $this;
        
        return $r;
    }
}