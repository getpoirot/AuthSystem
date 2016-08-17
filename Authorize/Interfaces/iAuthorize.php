<?php
namespace Poirot\AuthSystem\Authorize\Interfaces;

use Poirot\AuthSystem\Authenticate\Interfaces\iIdentity;

interface iAuthorize
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
     * @param iIdentity          $role
     * @param iResourceAuthorize $resource
     *
     * @return boolean
     */
    function isAllowed(iIdentity $role = null, iResourceAuthorize $resource = null);
}
