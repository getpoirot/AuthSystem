<?php
namespace Poirot\AuthSystem\Authorize\Interfaces;

use Poirot\AuthSystem\Authenticate\Interfaces\iIdentity;

interface iAuthPermission
{
    /**
     * Is allowed to features?
     *
     * - we can use this method event if no user identified
     *   in case that all users has access on home route from
     *   resource object, but only authorized users has access
     *   on other route names, and only AdminUser has access on
     *   admin route
     *
     * @param null|iIdentity     $role
     * @param null|iAuthResource $resource
     *
     * @return boolean
     */
    public function isAllowed(iIdentity $role = null, iAuthResource $resource = null);
}
