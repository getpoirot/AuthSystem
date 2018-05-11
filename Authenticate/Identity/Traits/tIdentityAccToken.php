<?php
namespace Poirot\AuthSystem\Authenticate\Identity\Traits;

use Poirot\ApiClient\Interfaces\Token\iAccessTokenObject;


trait tIdentityAccToken
{
    protected $accToken;


    /**
     * Set Access Token
     *
     * @param iAccessTokenObject $accToken
     *
     * @return $this
     */
    function setAccessToken(iAccessTokenObject $accToken)
    {
        $this->accToken = $accToken;
        return $this;
    }

    /**
     * Get Access Token
     *
     * @return iAccessTokenObject
     */
    function getAccessToken()
    {
        return $this->accToken;
    }
}
