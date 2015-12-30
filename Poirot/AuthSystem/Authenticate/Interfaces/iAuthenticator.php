<?php
namespace Poirot\AuthSystem\Authenticate\Interfaces;

use Poirot\AuthSystem\Authenticate\Exceptions\AuthenticationException;
use Poirot\AuthSystem\Authenticate\Exceptions\NotAuthenticatedException;
use Poirot\Core\Interfaces\iDataSetConveyor;

Interface iAuthenticator
{
    /**
     * Authenticate
     *
     * - authenticate user using credential
     * - login into identifier with iIdentity set from recognized
     *   user data
     *
     * note: after successful authentication, you must call
     *       login() outside of method to store identified user
     *
     * @param iCredential|iDataSetConveyor|array $credential
     *
     * @throws AuthenticationException Or extend of this
     * @return iIdentifier
     */
    function authenticate($credential = null);

    /**
     * Has Authenticated And Identifier Exists
     *
     * - it mean that Identifier has full filled identity
     *
     * note: this allow to register this authenticator as a service
     *       to retrieve authenticate information
     *
     * @return boolean
     */
    function hasAuthenticated();

    /**
     * Get Authenticated User Identifier
     *
     * note: this allow to register this authenticator as a service
     *       to retrieve authenticate information
     *
     * @return iIdentifier
     */
    function identifier();

    /**
     * Credential instance
     *
     * [code:]
     * // when options is passed it must init current credential and return
     * // self instead of credential
     *
     * $auth->credential([
     *   'username' => 'payam'
     *   , 'password' => '123456'
     *   , 'realm' => 'admin'
     *  ])->authenticate()
     * [code]
     *
     * - it`s contains credential fields used by
     *   authorize() to authorize user.
     *   maybe, user/pass or ip address in some case
     *   that we want auth. user by ip
     *
     * - it may be vary from within different Authorize
     *   services
     *
     * @param null|array $options
     *
     * @return $this|iCredential
     */
    function credential($options = null);
}
