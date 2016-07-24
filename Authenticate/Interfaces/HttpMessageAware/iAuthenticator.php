<?php
namespace Poirot\AuthSystem\Authenticate\Interfaces\HttpMessageAware;

use Poirot\AuthSystem\Authenticate\Interfaces\iAuthenticator as iBaseAuthenticator;
use Poirot\AuthSystem\Authenticate\Exceptions\exAuthentication;

use Poirot\Http\Interfaces\iHttpRequest;
use Poirot\Http\Interfaces\Respec\iRequestAware;

interface iAuthenticator 
    extends iBaseAuthenticator
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
     * @throws exAuthentication Or extend of this
     * @throws \Exception request invalid or etc.
     * @return $this
     */
    function authenticate(/* iHttpRequest */ $request = null);
}
