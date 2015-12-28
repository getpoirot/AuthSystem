<?php

namespace Poirot\AuthSystem\Authenticate;

use Poirot\AuthSystem\Authenticate\Exceptions\AuthenticationException;
use Poirot\AuthSystem\Authenticate\Interfaces\iAuthenticator;
use Poirot\AuthSystem\Authenticate\Interfaces\iCredential;
use Poirot\AuthSystem\Authenticate\Interfaces\iIdentifier;
use Poirot\AuthSystem\Authenticate\Interfaces\iIdentity;
use Poirot\Core\AbstractOptions;
use Poirot\Core\BuilderSetterTrait;

abstract class AbstractAuthenticator implements iAuthenticator
{
    use BuilderSetterTrait;

    /** @var iCredential */
    protected $credential;

    /** @var iIdentifier */
    protected $authenticated_identifier;

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
    abstract function authenticate();

    /**
     * Get Instance of credential Object
     *
     * @param null|array|AbstractOptions $options Builder Options
     *
     * @return iCredential
     */
    abstract function newCredential($options = null);

    /**
     * Proxy Helper To Identifier identity method
     *
     * ! identifier()->identity()
     * @see iIdentifier
     *
     * @return iIdentity|null
     */
    function hasAuthenticated()
    {
        return ($this->authenticated_identifier) ? $this->authenticated_identifier : false;
    }


    // ...

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
     * @return $this|iCredential
     */
    function credential($options = null)
    {
        if (!$this->credential)
            $this->credential = $this->newCredential();

        if ($options !== null) {
            $this->credential->from($options);
            return $this;
        }

        return $this->credential;
    }
}
