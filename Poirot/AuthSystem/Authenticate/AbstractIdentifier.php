<?php
namespace Poirot\AuthSystem\Authenticate;

use Poirot\AuthSystem\Authenticate\Exceptions\NotAuthenticatedException;
use Poirot\AuthSystem\Authenticate\Interfaces\iIdentifier;
use Poirot\AuthSystem\Authenticate\Interfaces\iIdentity;
use Poirot\Core\BuilderSetterTrait;
use Poirot\Storage\Adapter\CookieStorage;
use Poirot\Storage\Interfaces\iStorageEntity;

abstract class AbstractIdentifier implements iIdentifier
{
    use BuilderSetterTrait;

    const REALM = 'Poirot_Auth_Identifier';


    /** @var iIdentity */
    protected $identity;

    protected $_storage;
    protected $_cookie;

    /** @var boolean Remember user when login */
    protected $_remember = false;

    // options:
    /** @var iIdentity */
    protected $defaultIdentity;
    protected $realm;

    /**
     * Construct
     *
     * @param array|null $options
     */
    function __construct(array $options = null)
    {
        if ($options !== null)
            $this->setupFromArray($options);
    }

    /**
     * Get the storage object which identity stored in
     *
     * @return iStorageEntity
     */
    abstract function __storage();


    /**
     * Inject Identity
     *
     * @param iIdentity $identity Full Filled Identity
     *
     * @throws NotAuthenticatedException Identity not full filled
     * @return $this
     */
    function setIdentity(iIdentity $identity)
    {
        if (!$identity->isFullFilled())
            throw new NotAuthenticatedException;

        $this->identity = $identity;
        return $this;
    }

    /**
     * Get Authenticated User Data
     *
     * -
     *
     * @return iIdentity
     */
    function identity()
    {
        if($this->identity)
            return $this->identity;


        $defaultIdentity = $this->getDefaultIdentity();

        if($uid = $this->__storage()->get('uid'))
            ## if not identity loaded, load it to memory from authenticated user uid
            $this->setIdentity($defaultIdentity->setUid($uid));
        elseif ($this->isRemembered() && $uid = $this->__cookie()->get('uid')) {
            ## it's maybe found on cookie
            $this->login(); // log knowing user in
        }

        return $this->identity;
    }

    /**
     * Login Authenticated User
     *
     * - store current identity data into storage
     * - logout current user if has
     *
     * @throws \Exception no identity defined
     * @return $this
     */
    function login()
    {
        if (!($identity = $this->identity))
            throw new \Exception('No Identity Injected.');

        if ($this->_remember)
            $this->__cookie()->set('user', $identity->getUid());

        $this->__storage()->set('identity' , $identity);
        return $this;
    }

    /**
     * Logout Authenticated User
     *
     * - it must destroy storage data
     *
     * @return void
     */
    function logout()
    {
        $this->__storage()->destroy();
    }


    // ...

    /**
     * Has User Logged in?
     *
     * - login mean that user uid exists in the storage
     * - user that recognized in remember storage must
     *   has logged in to recognize here
     *
     * @return boolean
     */
    function isLogin()
    {
        if($this->__storage()->get('uid'))
            return true;

        return false;
    }


    // ...

    /**
     * Remember Me Feature!
     *
     * @param bool $flag
     *
     * @return $this
     */
    function setRemember($flag = true)
    {
        $this->_remember = $flag;
        return $this;
    }

    /**
     * Has any user data exists in storage and
     * can be recognized as any identified user?
     *
     * @return boolean
     */
    function isRemembered()
    {
        $return = ($this->__cookie()->get('uid', false) !== false) ? true : false;
        return $return;
    }


    // Options:

    /**
     * Set Realm To Limit Authentication
     *
     * ! mostly used as storage namespace to have
     *   multiple area for each different Authenticate system
     *
     * @param string $realm
     *
     * @return $this
     */
    function setRealm($realm)
    {
        $this->realm = (string) $realm;
        return $this;
    }

    /**
     * Get Realm Area
     *
     * @return string
     */
    function getRealm()
    {
        if (!$this->realm)
            $this->realm = self::REALM;

        return $this->realm;
    }

    /**
     * Set Default Identity Instance
     * @param iIdentity $identity
     * @return $this
     */
    function setDefaultIdentity(iIdentity $identity)
    {
        $this->defaultIdentity = $identity;
        return $this;
    }

    /**
     * Get Default Identity Instance
     * @return iIdentity
     */
    function getDefaultIdentity()
    {
        return $this->defaultIdentity;
    }


    // ...

    /**
     * Get Cookie Storage
     *
     * @return CookieStorage
     */
    protected function __cookie()
    {
        if (!$this->_cookie)
            $this->_cookie = new CookieStorage(['ident' => $this->getRealm()]);

        // insane but always used latest namespace
        $this->_cookie->options()->setIdent($this->getRealm());

        return $this->_cookie;
    }
}
