<?php

namespace Poirot\AuthSystem\Authenticate;


use Poirot\AuthSystem\Authenticate\Interfaces\iIdentifier;
use Poirot\AuthSystem\Authenticate\Interfaces\iIdentity;
use Poirot\Storage\Adapter\SessionStorage;


/**
 * Class AbstractIdentifier
 * @package Poirot\AuthSystem\Authenticate
 *
 */

abstract class AbstractIdentifier implements iIdentifier
{
    protected $identity;
    protected $storage;


    function __construct($storage = null)
    {
        if($storage != null)
            $this->storage = $storage;

        $this->storage = new SessionStorage(null);
    }

    function login(iIdentity $identity)
    {
        if($this->identity == true)
            throw new \Exception('the Identity is already loggedIn');

        $this->__getStorage()->set('identity' , $identity);
    }


    function logout()
    {
        if(!$this->storage)
            throw new \Exception('user already is not loggedIn');
        $this->storage->destroy();
    }

    function isLogin()
    {
        return $this->identity();
    }

    function identity()
    {
        /**
         * This method return identity instance registered
         * within this class
         * @return iIdentity|false
         */
        if($this->identity)
            return $this->identity;
        return false;
    }

    protected function __getStorage()
    {
        if (!$this->storage)
            $this->storage = $this::insStorage();

        return $this->storage;
    }

    protected abstract static function insStorage();

}