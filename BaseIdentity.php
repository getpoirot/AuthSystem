<?php
namespace Poirot\AuthSystem;

use Poirot\AuthSystem\Authenticate\Interfaces\iIdentity;
use Poirot\Storage\Adapter\CookieStorage;
use Poirot\Storage\Adapter\SessionStorage;

class BaseIdentity implements iIdentity
{
    /**
     * @var SessionStorage
     */
    protected $session;

    /**
     * @var CookieStorage
     */
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
     * @var boolean
     */
    protected $remember;

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
     * Set Identified User Id.
     *
     * - it always set from AuthAdapter::authenticate
     * - to complete authorize user login() must call
     *   after each setUserIdent to take effect,
     *   and knowing from hasAuthenticate method.
     *
     * @param mixed $identity User Identity
     *
     * @return $this
     */
    function setUserIdent($identity)
    {
        $this->userIdentity = $identity;

        return $this;
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
        $this->remember = $flag;

        return $this;
    }

    /**
     * Login Authorized User
     *
     * @return $this
     */
    function login()
    {
        if ($this->remember)
            $this->getCookie()->set('user', $this->userIdentity);

        $this->getSession()->set('user', $this->userIdentity);

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
        $this->getCookie()->destroy();

        return $this;
    }

    /**
     * Has Authenticated User?
     *
     * - if has authenticated user
     *   return identity
     *   else return false
     *
     * - never check remember flag
     *   the user that authenticated with
     *   Remember Me must recognized when
     *   exists.
     *
     * note: user must be login() to recognize here
     *
     * @return false|mixed
     */
    function hasAuthenticated()
    {
        if (!$user = $this->getSession()->get('user', false)) {
            // it's maybe found on cookie
            if ($user = $this->getCookie()->get('user', false)) {
                $curUsr = $this->userIdentity;
                $this->setUserIdent($user);
                $this->login(); // log knowing user in
                $this->setUserIdent($curUsr);
            }
        }

        return $user;
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
     * Get Cookie Storage
     *
     * @return SessionStorage
     */
    protected function getCookie()
    {
        if (!$this->cookie)
            $this->cookie = new CookieStorage(['ident' => $this->getNamespace()]);

        // insane but always used latest namespace
        $this->cookie->options()->setIdent(
            $this->getNamespace()
        );

        return $this->cookie;
    }
}
