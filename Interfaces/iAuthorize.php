<?php
namespace Poirot\Authentication\Interfaces;

use Poirot\Core\AbstractOptions;

interface iAuthorize
{
    /**
     * Change Authorization Namespace
     *
     * - isolate the authentication process
     *   used by storage to determine owned data
     *
     * @param string $namespace
     *
     * @return $this
     */
    function toNamespace($namespace);

    /**
     * Get Namespace
     *
     * @return string
     */
    function getCurrNamespace();

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
     * @return iCredential
     */
    function credential($options = null);

    /**
     * Authorize
     *
     * - throw exception from Authorize\Exceptions
     *   also you can throw your app meaning exception
     *   like: \App\Auth\UserBannedException
     *   to catch behaves
     *
     * - each time called will clean current storage
     * - after successful authentication it will fill
     *   the identity
     *   note: for iAuthorizeUserDataAware
     *         it used user data model to retrieve data
     *
     * @throws \Exception
     * @return $this
     */
    function authenticate();

    /**
     * Authorized User Identity
     *
     * - when ew have empty identity
     *   it means we have not authorized yet
     *
     * @return iIdentity
     */
    function identity();
}
