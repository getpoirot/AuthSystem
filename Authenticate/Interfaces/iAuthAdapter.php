<?php
namespace Poirot\AuthSystem\Authenticate\Interfaces;

use Poirot\AuthSystem\Authenticate\Exceptions\exAuthentication;
use Poirot\Std\Interfaces\Struct\iDataOptions;

interface iAuthAdapter 
    extends iDataOptions
{
    /**
     * @ignore
     *
     * Get Identity Match By Credential as Options
     *
     * @return iIdentity
     * @throws exAuthentication
     * @throws \Exception credential not fulfilled, etc..
     */
    function getIdentityMatch();


    // Options:

    /**
     * Set Realm
     * @param string $realm
     * @return $this
     */
    function setRealm($realm);

    /**
     * Get Realm
     * @return string|null
     */
    function getRealm();
    
    
    // Credential Options:
    
    // function setUsername();
}
