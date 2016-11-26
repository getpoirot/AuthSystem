<?php
namespace Poirot\AuthSystem\Authenticate\Interfaces;

use Poirot\AuthSystem\Authenticate\Exceptions\exAuthentication;
use Poirot\AuthSystem\Authenticate\Exceptions\exNotAuthenticated;

/**
 * Identifier is an object that recognize user in each request 
 * or tell that has no recognized user exists.
 * then we can achieve user data with identity that fulfilled with required
 * data.
 * 
 * Sign In/Out User as Identity into Environment(by session or something)
 *
 * - if identity is fulfilled/validated means user is recognized
 * - you can sign-in fulfillment identity
 * - sign-in/out take control of current identifier realm
 * - sign in some cases can be happen on request/response headers
 * 
 */
interface iIdentifier
{
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
    function setRealm($realm);

    /**
    * Get Realm Area
    *
    * @return string
    */
    function getRealm();
    
    /**
     * Set Immutable Identity
     * 
     * @param iIdentity $identity
     * 
     * @return $this
     * @throws \Exception immutable error; identity not met requirement
     */
    function giveIdentity(iIdentity $identity);

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
     * @throws exNotAuthenticated not set or cant recognized
     */
    function withIdentity();

    /**
     * Login Authenticated User
     *
     * - Sign user in environment and server
     *   exp. store in session, store data in cache
     *        sign user token in header, etc.
     *
     * @throws \Exception no identity defined
     * @return $this
     */
    function signIn();

    /**
     * Logout Authenticated User
     *
     * - it must destroy sign
     *   ie. destroy session or invalidate token in storage
     *
     * - destroy identity (immutable)
     *
     * @return void
     */
    function signOut();

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
    function canRecognizeIdentity();

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
    function issueException(exAuthentication $exception = null);
}
