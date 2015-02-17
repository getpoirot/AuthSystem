<?php
namespace Poirot\AuthSystem\Interfaces;

interface iUserDataModelProvider
{
    /**
     * Get User Data Model
     *
     * @return iUserDataEntityProvider
     */
    function getUserDataModel();
}
