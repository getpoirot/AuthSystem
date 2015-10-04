<?php

namespace Poirot\AuthSystem\Authenticate;

use Poirot\Storage\Adapter\SessionStorage;

class BaseIdentifier extends AbstractIdentifier
{

    function __construct()
    {

    }

    function __getStorage()
    {
        if(! $this->storage)
            $this->storage = new SessionStorage(['ident'=>'userAuth']);
        return $this->storage;
    }

}