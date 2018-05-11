<?php
namespace Poirot\AuthSystem\Authenticate\Interfaces\Identity;

use Poirot\ApiClient\Interfaces\Token\iAccessTokenObject;


interface iIdentityAccTokenProvider
{
    /**
     * Get Access Token
     *
     * @return iAccessTokenObject
     */
    function getAccessToken();
}
