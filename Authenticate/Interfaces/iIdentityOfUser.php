<?php
namespace Poirot\AuthSystem\Authenticate\Interfaces;


interface iIdentityOfUser
    extends iIdentity
{
    /**
     * Get User Unique Id
     *
     * @return mixed
     */
    function getOwnerId();

    /**
     * Data Embed With User Identity
     *
     * @param string $key
     *
     * @return array
     */
    function getMetaData($key = null);
}
