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
     * @param iCredential|null $credential
     *
     * @throws AuthenticationException
     * @throws \Exception credential or etc.
     * @return iIdentity
     */
    abstract function doIdentityMatch($credential = null);


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

    /**
     * Set Credential
     * @param iCredential $credential
     * @return $this
     */
    function setCredential(iCredential $credential)
    {
        $this->credential = $credential;
        return $this;
    }
}
