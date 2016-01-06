<?php
namespace Poirot\AuthSystem\Authenticate\Authenticator;

use Poirot\AuthSystem\Authenticate\AbstractHttpAuthenticator;
use Poirot\AuthSystem\Authenticate\Credential\UserPassCredential;
use Poirot\AuthSystem\Authenticate\Exceptions\AuthenticationException;
use Poirot\AuthSystem\Authenticate\Interfaces\iCredential;
use Poirot\AuthSystem\Authenticate\Interfaces\iIdentity;
use Poirot\Http\Message\HttpRequest;

class HttpSessionAuth extends AbstractHttpAuthenticator
{
    /**
     * Do Extract Credential From Request Object
     * ie. post form data or token
     *
     * @param HttpRequest $request
     *
     * @throws AuthenticationException if auth credential not available
     *         it cause user get authorize require response
     *
     * @return iCredential
     */
    function doExtractCredentialFromRequest(HttpRequest $request)
    {
        if ($request->plg()->methodType()->isPost()) {
            $POST       = $request->plg()->phpServer()->getPost();
            $credential = new UserPassCredential([
                'username' => $POST->get('email'),
                'password' => $POST->get('password'),
            ]);

            return $credential;
        }

        $this->riseException(new AuthenticationException);
    }

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
