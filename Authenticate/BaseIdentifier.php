<?php

namespace Poirot\AuthSystem\Authenticate;

use Poirot\Storage\Adapter\SessionStorage;

class BaseIdentifier extends AbstractIdentifier
{

    function __construct()
    {

    }

    static function insStorage()
    {
        if(! self::$storage)
            self::$storage = new SessionStorage(['ident'=>'userAuth']);
        return self::$storage;
    }

}