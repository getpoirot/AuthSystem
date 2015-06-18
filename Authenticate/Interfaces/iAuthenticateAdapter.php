<?php
namespace Poirot\AuthSystem\Authenticate\Interfaces;

use Poirot\Core\AbstractOptions;

interface iAuthenticateAdapter
{
    /**
     * Authorize
     *
     * - throw exception from Authorize\Exceptions
     *   also you can throw your app meaning exception
     *   like: \App\Auth\UserBannedException
     *   to catch behaves
     *
     * - set authenticated user identity
     *   $this->identity()->setUserIdentity($user_identity)
     *
     * note: each time called will clean current storage
     *       can happen with $this->identity()->logout()
     *
     * note: after successful authentication, you must call
     *       login() outside of method to store identified user
     *
     * note: for iAuthorizeUserDataAware
     *       it used user data model to retrieve data
     *       on authentication in case of user isActive
     *       and so on ...
     *
     * @throws \Exception
     * @return $this
     */
    function authenticate();

    /**
     * Set Authorized User Identity
     *
     * @param iIdentity $identity
     *
     * @return $this
     */
    function setIdentity(iIdentity $identity);

    /**
     * Get Authorized User Identity
     *
     * - when we have empty identity
     *   it means we have not authorized yet
     *
     * ! don't use default identity creation on get if not
     *   any identity available
     *
     *   identities must inject into adapter by auth services
     *
     * @throws \Exception Not Identity Available Or Set
     * @return iIdentity
     */
    function getIdentity();

    /**
     * Credential
     *
     * - it`s contains credential fields used by
     *   authorize() to authorize user.
     *   maybe, user/pass or ip address in some case
     *   that we want auth. user by ip
     *
     * - it may be vary from within different Authorize
     *   services
     *
     * @param null|array|AbstractOptions $options Builder Options
     *
     * @return $this|iCredential
     */
    function credential($options = null);
}
