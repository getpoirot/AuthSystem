<?php
namespace Poirot\AuthSystem\Authenticate\Interfaces;

use Poirot\AuthSystem\Authenticate\Exceptions\exAuthentication;
use Poirot\Std\Interfaces\Struct\iDataOptions;

interface iAuthAdapter 
    extends iDataOptions
{
    /**
     * Get Identity Match By Credential
     *
     * @param iCredential|null $credential Fulfilled Credential
     *
     * @ignore
     * @return iIdentity
     * @throws exAuthentication
     * @throws \Exception credential or etc.
     */
    function getIdentityMatch($credential = null);

    /**
     * Credential
     *
     * @return iCredential
     */
    static function newCredential();


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

    /**
     * Set Credential
     *
     * @param iCredential $credential
     *
     * @return $this
     */
    function setCredential(iCredential $credential);
}
