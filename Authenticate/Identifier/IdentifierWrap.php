<?php
namespace Poirot\AuthSystem\Authenticate\Identifier;

use Poirot\AuthSystem\Authenticate\Exceptions\exAuthentication;
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
        $this->identifier->withIdentity()->import($this->withIdentity());
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
        $this->withIdentity()->clean();
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
     * Set Immutable Identity
     *
     * @param iIdentity $identity
     *
     * @return $this
     * @throws \Exception immutable error; identity not met requirement
     */
    function giveIdentity(iIdentity $identity)
    {
        $this->identifier->giveIdentity($identity);
        return $this;
    }
    
    /**
     * Get Authenticated User Data Copy
     *
     * - for check that user is signIn the identity must
     *   fulfilled.
     * - if canRecognizeIdentity extract data from it
     *   this cause identity fulfillment with given data
     *   ie. when user exists in session build identity from that
     *
     * @return iIdentity
     */
    function withIdentity()
    {
        return $this->identifier->withIdentity();
    }

    /**
     * Issue To Handle Authentication Exception
     *
     * usually called when authentication exception rise
     * to challenge client to login form or something.
     *
     * [code:]
     * // ..
     * } catch (P\AuthSystem\Authenticate\Exceptions\exAuthentication $e) {
     *     echo '<h1>You MUST Login:</h1>';
     *     // Challenge User For Credential Login:
     *     # $e->issueException(); // recommended
     *     $e->getAuthenticator()->identifier()->issueException();
     * }
     * [code]
     *
     * @param exAuthentication $exception Maybe support for specific error
     *
     * @return mixed Result Handle in Dispatch Listener Events
     */
    function issueException(exAuthentication $exception = null)
    {
        return $this->identifier->issueException($exception);
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