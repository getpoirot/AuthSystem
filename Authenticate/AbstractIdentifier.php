<?php
namespace Poirot\AuthSystem\Authenticate;

use Poirot\AuthSystem\Authenticate\Interfaces\iIdentifier;
use Poirot\AuthSystem\Authenticate\Interfaces\iIdentity;

abstract class AbstractIdentifier implements iIdentifier
{
    protected $identity;
    protected static $storage;

    function login(iIdentity $identity)
    {
        if($this->identity == true)
            throw new \Exception('the Identity is already loggedIn');

        $this->__getStorage()->set('identity' , $identity);
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
     * @return false|iIdentity
     */

    function isLogin()
    {
        return $this->identity();
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
        return false;
    }

    protected function __getStorage()
    {
        if (! self::$storage)
            self::$storage = static::insStorage();

        return self::$storage;
    }

    protected static function insStorage()
    {

    }

}