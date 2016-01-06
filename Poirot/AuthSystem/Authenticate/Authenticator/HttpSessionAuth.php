<?php
namespace Poirot\AuthSystem\Authenticate\Authenticator;

use Poirot\AuthSystem\Authenticate\AbstractHttpAuthenticator;
use Poirot\AuthSystem\Authenticate\Interfaces\iIdentity;

class HttpSessionAuth extends AbstractHttpAuthenticator
{
    /**
     * Attain Identity Object From Signed Sign
     * @see identity()
     * @return iIdentity
     */
    function attainSignedIdentity()
    {
        // TODO: Implement attainSignedIdentity() method.
    }

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
        // TODO: Implement signIn() method.
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
        // TODO: Implement signOut() method.
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
        // TODO: Implement isSignIn() method.
    }
}
