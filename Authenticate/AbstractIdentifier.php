<?php
namespace Poirot\AuthSystem\Authenticate;

use Poirot\AuthSystem\Authenticate\Interfaces\iIdentifier;
use Poirot\AuthSystem\Authenticate\Interfaces\iIdentity;

abstract class AbstractIdentifier implements iIdentifier
{
    protected $identity;
    protected static $storage;


    /**
     * @param iIdentity $identity
     * @return $this
     */
    function login(iIdentity $identity)
    {
        $this->__getStorage()->set('identity' , $identity);
        return $this;
    }


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
        else if($this->insStorage()->get('identity'))
            $this->identity = $this->insStorage()->get('identity');
        else
            return false;

        return $this->identity;
    }

    protected function __getStorage()
    {
        if (! self::$storage)
            self::$storage = static::insStorage();

        return self::$storage;
    }

    abstract static function insStorage();

}