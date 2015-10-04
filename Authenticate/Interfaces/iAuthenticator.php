<?php
namespace Poirot\AuthSystem\Authenticate\Interfaces;

use Poirot\AuthSystem\Authenticate\Exceptions\AuthenticationException;

Interface iAuthenticator
{
    /**
     * Set Identifier
     *
     * @param iIdentifier $identifier
     *
     * @return $this
     */
    function setIdentifier(iIdentifier $identifier);

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
     * Identifier instance
     *
     * @return iIdentifier
     */
    function identifier();

    /**
     * Proxy Helper To Identifier identity method
     *
     * ! identifier()->identity()
     *
     * @throws AuthenticationException
     * @return iIdentity
     */
    function getIdentity();

    /**
     * Credential instance
     *
     * @param $options
     * @return $this|iCredential
     */
    function credential($options=null);
}
