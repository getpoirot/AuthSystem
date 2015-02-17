<?php
namespace Poirot\AuthSystem\Authenticate\Interfaces;

use Poirot\Core\AbstractOptions;
use Poirot\Core\Interfaces\iPoirotOptions;

interface iCredential extends iPoirotOptions
{
    /**
     * If Authorization was successful identity
     * will use this to fill user data from
     * adapter to identity
     *
     * ! in database it can be a unique field like
     *   mailAddress, pk, ...
     *
     * @return mixed
     */
    function getUserIdentity();
}
