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
     * @param null|iAuthResource $resource
     * @param null|iIdentity     $role
     *
     * @return boolean
     */
    public function isAllowed(/*iAuthResource*/ $resource = null, /*iIdentity*/ $role = null);
}
