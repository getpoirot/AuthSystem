<?php
namespace Poirot\Authentication\Interfaces;

interface iAuthorizeUserDataProvider
{
    /**
     * Get User Data Model
     *
     * @return iUserDataModelProvider
     */
    function getUserDataModel();
}
