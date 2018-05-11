<?php
namespace Poirot\AuthSystem\Authenticate\Interfaces\Identity;

use Poirot\ApiClient\Interfaces\Token\iAccessTokenObject;


interface iIdentityAccTokenAware
{
    /**
     * Set Access Token
     *
     * @param iAccessTokenObject $accToken
     *
     * @return $this
     */
    function setAccessToken(iAccessTokenObject $accToken);
}
