<?php
namespace Poirot\AuthSystem\Authenticate\Authenticator\Adapter;

use Poirot\AuthSystem\Authenticate\Exceptions\AuthenticationException;
use Poirot\AuthSystem\Authenticate\Interfaces\iAuthAdapter;
use Poirot\AuthSystem\Authenticate\Interfaces\iCredential;
use Poirot\AuthSystem\Authenticate\Interfaces\iIdentity;
use Poirot\Core\AbstractOptions;

abstract class AbstractAuthAdapter extends AbstractOptions
    implements iAuthAdapter
{
    protected $credential;
    protected $realm;

    /**
     * Get Identity Match By Identity
     *
     * @param iCredential $credential
     *
     * @throws AuthenticationException
     * @throws \Exception credential or etc.
     * @return iIdentity
     */
    abstract function doIdentityMatch($credential);


    // ...

    /**
     * Set Realm
     * @param string $realm
     * @return $this
     */
    function setRealm($realm)
    {
        $this->realm = $realm;
        return $this;
    }

    /**
     * Get Realm
     * @return string|null
     */
    function getRealm()
    {
        return $this->realm;
    }
}
