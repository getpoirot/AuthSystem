<?php
namespace Poirot\AuthSystem\Authorize\Interfaces;

use Poirot\AuthSystem\Authenticate\Interfaces\iIdentity;

interface iAuthPermission
{
    /**
     * Is allowed to features?
     *
     * @param null|iIdentity     $role
     * @param null|iAuthResource $resource
     *
     * @return boolean
     */
    public function isAllowed(iIdentity $role = null, iAuthResource $resource = null);
}
