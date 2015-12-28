<?php

namespace Poirot\AuthSystem\Authenticate;

use Poirot\Storage\Adapter\SessionStorage;

class BaseIdentifier extends AbstractIdentifier
{
    function __getStorage()
    {
        if(! $this->_storage)
            $this->_storage = new SessionStorage(['ident'=>'userAuth']);
        return $this->_storage;
    }
}
