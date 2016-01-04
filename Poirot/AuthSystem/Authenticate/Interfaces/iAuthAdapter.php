<?php
namespace Poirot\AuthSystem\Authenticate\Interfaces;

use Poirot\AuthSystem\Authenticate\Exceptions\AuthenticationException;
use Poirot\Core\Interfaces\iOptionImplement;

interface iAuthAdapter extends iOptionImplement
{
    /**
     * Get Identity Match By Identity
     *
     * @param iCredential $credential
     *
     * @throws AuthenticationException
     * @throws \Exception credential or etc.
     * @return iIdentity
     */
    function doIdentityMatch($credential);

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
}
