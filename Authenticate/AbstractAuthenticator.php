<?php

namespace Poirot\AuthSystem\Authenticate;

use Poirot\AuthSystem\Authenticate\Exceptions\AuthenticationException;
use Poirot\AuthSystem\Authenticate\Interfaces\iAuthenticator;
use Poirot\AuthSystem\Authenticate\Interfaces\iCredential;
use Poirot\AuthSystem\Authenticate\Interfaces\iIdentifier;
use Poirot\Core\BuilderSetterTrait;

abstract class AbstractAuthenticator implements iAuthenticator
{
    use BuilderSetterTrait;

    /**
     * @var iCredential
     */
    protected $credential;

    /**
     * @var iIdentifier
     */
    protected $identifier;


    /**
     * Proxy Helper To Identifier identity method
     *
     * ! identifier()->identity()
     *
     * @return null|iIdentity
     */
    function getIdentity()
    {
        return $this->identifier()->identity();
    }




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
    function identifier()
    {
        if (!$this->identifier)
            throw new \Exception('No Identifier Object Available on this instance of AbstractAuthenticator class.');

        return $this->identifier;
    }

    /**
     * Credential
     *
     * - it`s contains credential fields used by
     *   authenticate() to authenticate user.
     *   maybe, user/pass or ip address in some case
     *   that we want auth. user by ip
     *
     * - it may be vary from within different Authentication
     *   services
     *
     * @param null|array|AbstractOptions $options Builder Options
     *
     * @throws \Exception credential object has been set
     * @return iCredential
     */
    function credential($options = null)
    {
        if($options !== null && $this->credential)
            throw new \Exception('credential object has been set . if you want to change options reset credential object');

        if ($this->credential)
            return $this->credential;

        if ($options !== null) {
            $this->credential = $this->insCredential($options);
        }

        return $this->credential;
    }

    /**
     * Get Instance of credential Object
     *
     * @param null|array|AbstractOptions $options Builder Options
     *
     * @return iCredential
     */
    protected abstract function insCredential($options);
}



//
//$auth = (new Authenticator)
//    ->credental(
//        AbstrctAuthenticator::insCredential()
//            ->setUsername('majid')
//    )
//    ->authenticate();