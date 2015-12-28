<?php
namespace Poirot\AuthSystem\Authenticate;

use Poirot\AuthSystem\Authenticate\Interfaces\iIdentifier;
use Poirot\AuthSystem\Authenticate\Interfaces\iIdentity;

abstract class AbstractIdentifier implements iIdentifier
{
    protected $identity;

    protected $_storage;

    /**
     * Get the storage object which identity stored in
     *
     * @return mixed
     */
    abstract function __getStorage();

    /**
     * @param iIdentity $identity
     * @return $this
     */
    function login(iIdentity $identity)
    {
        $this->__getStorage()->set('identity' , $identity);
        return $this;
    }

    /**
     * @throws \Exception
     */
    function logout()
    {
        if(!$this->identity)
            throw new \Exception('user already is not loggedIn');
        $this->__getStorage()->destroy();
    }


    /**
     * isLogin
     *
     * Check is identity loggedIn or not
     *
     * @return boolean
     */

    function isLogin()
    {
        if($this->identity())
            return true;
        return false;
    }


    /**
     * This method return identity instance
     * registered within this class
     *
     * @return iIdentity|false
     */
    function identity()
    {
        if($this->identity)
            return $this->identity;
        else if($this->__getStorage()->get('identity'))
            $this->identity = $this->__getStorage()->get('identity');
        else
            return false;

        return $this->identity;
    }
}
