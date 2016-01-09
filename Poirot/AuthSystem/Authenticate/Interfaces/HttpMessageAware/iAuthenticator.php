<?php
namespace Poirot\AuthSystem\Authenticate\Interfaces\HttpMessageAware;

use Poirot\AuthSystem\Authenticate\Exceptions\AuthenticationException;
use Poirot\Http\Interfaces\Message\iHttpRequest;
use Poirot\Http\Interfaces\Respec\iRequestAware;

interface iAuthenticator extends \Poirot\AuthSystem\Authenticate\Interfaces\iAuthenticator
    , iRequestAware
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
     * @param iHttpRequest $request
     *
     * @throws AuthenticationException Or extend of this
     * @throws \Exception request invalid or etc.
     * @return $this
     */
    function authenticate(/* iHttpRequest */ $request = null);
}
