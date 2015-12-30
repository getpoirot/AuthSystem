<?php

namespace Poirot\AuthSystem\Authenticate;

use Poirot\Storage\Adapter\SessionStorage;

class BaseIdentifier extends AbstractIdentifier
{
    function __storage()
    {
        if(!$this->_storage)
            $this->_storage = new SessionStorage(['ident' => $this->getRealm()]);

        return $this->_storage;
    }
}
