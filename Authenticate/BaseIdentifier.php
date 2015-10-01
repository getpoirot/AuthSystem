<?php

namespace Poirot\AuthSystem\Authenticate;

use Poirot\Storage\Adapter\SessionStorage;

class BaseIdentifier extends AbstractIdentifier
{

    function __construct($storage = null)
    {
        if($storage != null)
            self::$storage = $storage;

        self::$storage = new SessionStorage(['ident'=>'userAuth']);
    }

    static function insStorage()
    {
        if(! self::$storage)
            throw new \Exception('Storage instance is not accessible');
        return self::$storage;
    }

}