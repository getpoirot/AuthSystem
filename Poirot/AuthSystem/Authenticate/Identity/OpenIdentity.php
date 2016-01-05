<?php
namespace Poirot\AuthSystem\Authenticate\Identity;

use Poirot\AuthSystem\Authenticate\AbstractIdentity;

class OpenIdentity extends AbstractIdentity
{
    /**
     * Is Identity Full Filled
     *
     * - full filled mean that all needed data
     *   set for this identity.
     *
     *   ! it's usually is enough to have uid
     *
     * @return boolean
     */
    function isFulfilled()
    {
        return true;
    }
}
