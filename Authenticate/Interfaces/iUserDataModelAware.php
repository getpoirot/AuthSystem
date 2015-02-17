<?php
namespace Poirot\AuthSystem\Authenticate\Interfaces;

interface iUserDataModelAware
{
    /**
     * Set User Data Model
     *
     * @param iUserDataEntityProvider $userModel
     *
     * @return $this
     */
    function setUserDataModel(iUserDataEntityProvider $userModel);
}
