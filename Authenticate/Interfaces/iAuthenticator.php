<?php
namespace Poirot\AuthSystem\Authenticate\Interfaces;

use Poirot\AuthSystem\Authenticate\Exceptions\AuthenticationException;

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
     * @throws AuthenticationException Or extend of this
     * @return iIdentifier
     */
    function authenticate();

    /**
     * Proxy Helper To Identifier identity method
     *
     * ! identifier()->identity()
     * @see iIdentifier
     *
     * @throws AuthenticationException
     * @return iIdentity|null
     */
    function hasAuthenticated();

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
