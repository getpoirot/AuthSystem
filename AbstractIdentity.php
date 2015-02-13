<?php
namespace Poirot\Authentication;

use Poirot\Authentication\Interfaces\iIdentity;
use Poirot\Storage\Adapter\SessionStorage;

class AbstractIdentity implements iIdentity
{
    /**
     * @var $authorize
     */
    protected $authorize;

    /**
     * @var SessionStorage
     */
    protected $session;

    protected $cookie;

    /**
     * Authorize Service Namespace
     *
     * @var string
     */
    protected $namespace;

    /**
     * User Identity bu Authorize Service
     * ! it given from credential
     * @var string
     */
    protected $userIdentity;

    /**
     * Construct
     *
     * @param string $namespace
     */
    function __construct($namespace)
    {
        $this->setNamespace($namespace);
    }

    /**
     * Get Session Storage
     *
     * @return SessionStorage
     */
    protected function getSession()
    {
        if (!$this->session)
            $this->session = new SessionStorage(['ident' => $this->getNamespace()]);

        // insane but always used latest namespace
        $this->session->options()->setIdent(
            $this->getNamespace()
        );

        return $this->session;
    }

    /**
     * Set Namespace
     *
     * @param string $namespace
     *
     * @return $this
     */
    function setNamespace($namespace)
    {
        $this->namespace = $namespace;

        return $this;
    }

    /**
     * Get Namespace
     *
     * @return string
     */
    function getNamespace()
    {
        return $this->namespace;
    }

    /**
     * Set User Identity
     *
     * - it always set from AuthService::authorize
     *   found with AuthService::credential::getUserIdentity
     *
     * @param string $identity User Identity
     *
     * @return $this
     */
    function setUserIdentity($identity)
    {
        $this->userIdentity = $identity;

        return $this;
    }

    /**
     * Get User Identity
     *
     * @return string
     */
    function getUserIdentity()
    {
        return $this->userIdentity;
    }

    /**
     * Remember Me Feature!
     *
     * @param bool $flag
     *
     * @return $this
     */
    function setRemember($flag = true)
    {
        // TODO: Implement setRemember() method.
    }

    /**
     * Login Authorized User
     *
     * @return $this
     */
    function login()
    {
        // TODO: Implement Remember Me

        if ($this->getSession()->get('user') !== $this->getUserIdentity())
            $this->getSession()->set(
                'user',
                $this->getUserIdentity()
            );

        return $this;
    }

    /**
     * Clear Credential Entry
     *
     * - it must clear storage data
     * - it must destroy persist code
     *
     * @return $this
     */
    function logout()
    {
        $this->getSession()->destroy();

        return $this;
    }

    /**
     * Has Authenticated User?
     *
     * - if has authenticated user return identity
     *   else return false
     *
     * @return false|mixed
     */
    function hasAuthenticated()
    {
        if (!$this->getSession()->has('user'))
            return false;

        return $this->getSession()->get('user');
    }
}
