<?php
namespace Poirot\AuthSystem\Authenticate;

use Poirot\AuthSystem\Authenticate\Interfaces\iIdentifier;
use Poirot\AuthSystem\Authenticate\Interfaces\iIdentity;
use Poirot\Core\BuilderSetterTrait;
use Poirot\Storage\Interfaces\iStorageEntity;

abstract class AbstractIdentifier implements iIdentifier
{
    use BuilderSetterTrait;

    /** @var iIdentity */
    protected $__identity;
    protected $_with_identity;

    protected $_storage;

    /**
     * Construct
     *
     * @param array|null $options
     */
    function __construct(array $options = null)
    {
        $this->setupFromArray($options);
    }

    /**
     * Inject Identity
     *
     * @param iIdentity $identity
     *
     * @return $this
     */
    function setIdentity(iIdentity $identity)
    {
        $this->__identity = $identity;
        return $this;
    }


    /**
     * Get the storage object which identity stored in
     *
     * @return iStorageEntity
     */
    abstract function __getStorage();

    /**
     * Login Authenticated User
     *
     * - store current identity data into storage
     *
     * @throws \Exception no identity defined
     * @return $this
     */
    function login()
    {
        if (!($identity = $this->__identity))
            throw new \Exception('No Identity Injected.');

        $this->__getStorage()->set('identity' , $identity);
        return $this;
    }

    /**
     * @throws \Exception
     */
    function logout()
    {
        if(!$this->isLogin())
            throw new \Exception('user already is not loggedIn');

        $this->__getStorage()->destroy();
        $this->_with_identity = null;
    }


    // ...

    /**
     * isLogin
     *
     * Check is identity loggedIn or not
     *
     * @return boolean
     */

    function isLogin()
    {
        if($this->withIdentity())
            return true;

        return false;
    }

    /**
     * Get User Identity
     *
     * - if user has logged in get identity from
     *   storage otherwise return null
     *
     * @return null|iIdentity
     */
    function withIdentity()
    {
        if($this->_with_identity)
            return $this->_with_identity;
        else if($this->__getStorage()->get('identity'))
            $this->_with_identity = $this->__getStorage()->get('identity');
        else
            return null;

        return $this->_with_identity;
    }
}
