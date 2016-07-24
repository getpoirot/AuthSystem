<?php
namespace Poirot\AuthSystem\Authenticate\Authenticator\Adapter;

use Poirot\AuthSystem\Authenticate\Exceptions\exAuthentication;
use Poirot\AuthSystem\Authenticate\Interfaces\iAuthAdapter;
use Poirot\AuthSystem\Authenticate\Interfaces\iIdentity;
use Poirot\Std\Struct\aDataOptions;

/**
 * @method getIdentityMatch($credential = null) @ignore
 */
abstract class aAuthAdapter
    extends aDataOptions
    implements iAuthAdapter
{
    protected $credential;
    protected $realm;

    /**
     * @ignore
     *
     * Get Identity Match By Credential as Options
     *
     * @return iIdentity
     * @throws exAuthentication
     * @throws \Exception credential not fulfilled, etc..
     */
    final function getIdentityMatch()
    {
        if (!$this->isFulfilled())
            throw new \Exception('Adapter Options Not Fulfilled To Retrieve Identity Match.');

        return $this->doIdentityMatch(\Poirot\Std\cast($this)->toArray());
    }

    /**
     * Do Match Identity With Given Options/Credential
     *
     * @param array $options Include Credential Data
     *
     * @return iIdentity
     */
    abstract function doIdentityMatch(array $options);

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
