<?php
namespace Poirot\Authentication\Interfaces;

use Poirot\Core\AbstractOptions;
use Poirot\Core\Interfaces\iMagicalFields;

interface iCredential extends iMagicalFields
{
    /**
     * Remember Me Feature!
     *
     * @param bool $flag
     *
     * @return $this
     */
    function setRemember($flag = true);

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
