<?php
namespace Poirot\Authentication\Interfaces;

interface iAuthorizeUserDataAware
{
    /**
     * Set User Data Model
     *
     * @param iUserDataModelProvider $userModel
     *
     * @return $this
     */
    function setUserDataModel(iUserDataModelProvider $userModel);
}
