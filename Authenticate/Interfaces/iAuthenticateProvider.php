<?php
namespace Poirot\AuthSystem\Authenticate\Interfaces;

interface iAuthenticateProvider 
{
    /**
     * Get Authenticate Adapter
     *
     * @return iAuthenticateAdapter
     */
    function getAuthAdapter();
}
