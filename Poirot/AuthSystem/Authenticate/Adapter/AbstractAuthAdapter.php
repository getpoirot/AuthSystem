<?php
namespace Poirot\AuthSystem\Authenticate\Adapter;

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
     * @return iIdentity
     */
    abstract function doIdentityMatch($credential);

    /**
     * Credential Instance
     *
     * @param iCredential|array|null $options
     *
     * @return iCredential|$this
     */
    function credential($options = null)
    {
        if (!$this->credential)
            $this->credential = $this->newCredential();

        if ($options !== null) {
            $this->credential->from($options);
            return $this;
        }

        return $this->credential;
    }

    /**
     * @return iCredential
     */
    abstract protected function newCredential();

    /**
     * Set Credential
     * @param iCredential|array $options
     * @return $this
     */
    function setCredential($options)
    {
        $this->credential($options);
        return $this;
    }

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
