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
     * @return iIdentity
     */
    function doIdentityMatch($credential);

    /**
     * Credential Instance
     *
     * @param iCredential|array|null $options
     *
     * @return iCredential|$this
     */
    function credential($options = null);


    // Options:

    /**
     * Set Credential
     * @param iCredential|array $options
     * @return $this
     */
    function setCredential($options);

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
