<?php
namespace Poirot\Authentication;

use Poirot\Authentication\Interfaces\iAuthorize;
use Poirot\Authentication\Interfaces\iIdentity;
use Poirot\Storage\Interfaces\iStorage;

class AbstractIdentity implements iIdentity
{
    /**
     * @var iStorage
     */
    protected $storage;

    /**
     * @var $authorize
     */
    protected $authorize;

    /**
     * Construct
     *
     * @param iAuthorize $authorize
     * @param iStorage $storage
     */
    function __construct(iAuthorize $authorize, iStorage $storage)
    {
       $this
           ->injectAuthAdapter($authorize)
           ->injectStorage($storage);
    }

    /**
     * Login Authorized User
     *
     * @return $this
     */
    function login()
    {
        // TODO: Implement login() method.
    }

    /**
     * Clear Credential Entry
     *
     * - it must clear storage data
     * - it must destroy persist code
     *
     * @return $this
     */
    function logout()
    {
        $this->storage()->destroy();

        return $this;
    }

    /**
     * Is Identity Storage Empty
     *
     * -
     *
     * @return boolean
     */
    function isEmpty()
    {
        return ( count($this->storage()->keys()) == 0 );
    }

    /**
     * Inject Authorize Adapter
     *
     * @param iAuthorize $authorize
     *
     * @return $this
     */
    function injectAuthAdapter(iAuthorize $authorize)
    {
        $this->authorize = $authorize;

        return $this;
    }

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
    function injectStorage(iStorage $storage)
    {
        $this->storage = $storage;

        return $this;
    }

    /**
     * Authorized User Data Storage
     *
     * ! storage Identity must be override
     *   that storage only be valid on this credential
     *   namespace
     *
     * @throws \Exception
     * @return iStorage
     */
    function storage()
    {
        if (!$this->storage)
            throw new \Exception('Storage Not Injected.');

        return $this->storage;
    }
}
 