<?php
namespace Poirot\AuthSystem\Authenticate\Interfaces;

use Poirot\AuthSystem\Authenticate\Exceptions\NotAuthenticatedException;

/**
 * Sign In/Out User as Identity into Environment
 *
 */
interface iIdentifier
{
    /**
     * Inject Identity
     *
     * @param iIdentity $identity Full Filled Identity
     *
     * @throws NotAuthenticatedException Identity not full filled
     * @return $this
     */
    function setIdentity(iIdentity $identity);

    /**
     * Get Authenticated User Data
     *
     * - if identity exists use it
     * - otherwise if signIn extract data from it
     *   ie. when user exists in session build identity from that
     *
     * - not one of above situation return empty identity
     *
     * @return iIdentity
     */
    function identity();


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
    function signIn();

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
    function signOut();

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
    function isSignIn();
}
