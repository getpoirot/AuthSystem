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
    protected $identifier;

    /**
     * Authenticate
     *
     * - throw exception from Authenticate\Exceptions
     *   also you can throw your app meaning exception
     *   like: \App\Auth\UserBannedException
     *   to catch behaves
     *
     * - each time called will clean current storage
     * - after successful authentication, you must call
     *   login() to save identified user
     *
     *   note: for iAuthorizeUserDataAware
     *         it used user data model to retrieve data
     *         on authentication in case of user isActive
     *         and so on ...
     *
     * @throws AuthenticationException
     * @return $this
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
     *
     * @throws AuthenticationException
     * @return iIdentity
     */
    function hasAuthenticated()
    {
        return $this->_getIdentifier()->identity();
    }


    // ...

    /**
     * Set Identifier instance which is responsible
     * for user login,logout,... of user
     *
     * @param iIdentifier $identifier
     *
     * @return $this
     */
    function setIdentifier(iIdentifier $identifier)
    {
        $this->identifier = $identifier;

        return $this;
    }

    /**
     * Get identifier object
     *
     * @throws \Exception No Identity Available Or Set
     * @return iIdentifier
     */
    protected function _getIdentifier()
    {
        if (!$this->identifier)
            throw new \Exception('No Identifier Object Available on this instance of AbstractAuthenticator class.');

        return $this->identifier;
    }

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
