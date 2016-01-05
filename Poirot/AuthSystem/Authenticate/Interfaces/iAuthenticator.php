<?php
namespace Poirot\AuthSystem\Authenticate\Interfaces;

use Poirot\AuthSystem\Authenticate\Exceptions\AuthenticationException;
use Poirot\Core\Interfaces\iDataSetConveyor;

Interface iAuthenticator extends iIdentifier
{
    /**
     * Authenticate
     *
     * - authenticate user using credential
     * - login into identifier with iIdentity set from recognized
     *   user data
     *
     * - it can be used to force user for login on each page that
     *   need access control
     *   ie. $auth->authenticate()
     *   if it has authenticated and not new credential passed as
     *   argument it will return and do nothing
     *
     * note: after successful authentication, you must call
     *       login() outside of method to store identified user
     *
     * @param iCredential|iDataSetConveyor|array $credential
     *
     * @throws AuthenticationException|\Exception Or extend of this
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
}
