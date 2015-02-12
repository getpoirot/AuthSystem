<?php
namespace Poirot\Authentication\Interfaces;

use Poirot\Storage\Interfaces\iStorage;

interface iIdentity
{
    /**
     * Login Authorized User
     *
     * @return $this
     */
    function login();

    /**
     * Clear Credential Entry
     *
     * - it must clear storage data
     * - it must destroy persist code
     *
     * @return $this
     */
    function logout();

    /**
     * Is Identity Storage Empty
     *
     * @return boolean
     */
    function isEmpty();

    /**
     * Inject Storage Used For Authorized User Data
     *
     * - with changing storage type we can
     *   implement Remember Me feature.
     *   Session, File, NonePersist, ...
     *
     * @param iStorage $storage
     *
     * @return $this
     */
    function injectStorage(iStorage $storage);

    /**
     * Authorized User Data Storage
     *
     * ! storage Identity must be override
     *   that storage only be valid on this credential
     *   namespace
     *
     * @return iStorage
     */
    function storage();
}
