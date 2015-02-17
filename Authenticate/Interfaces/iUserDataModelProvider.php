<?php
namespace Poirot\AuthSystem\Authenticate\Interfaces;

interface iUserDataModelProvider
{
    /**
     * Get User Data Model
     *
     * @return iUserDataEntityProvider
     */
    function getUserDataModel();
}
