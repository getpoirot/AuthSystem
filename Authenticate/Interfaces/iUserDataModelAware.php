<?php
namespace Poirot\AuthSystem\Interfaces;

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
