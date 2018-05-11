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
     * @return array
     */
    function getMetaData();
}
