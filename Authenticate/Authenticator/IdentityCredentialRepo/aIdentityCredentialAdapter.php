<?php
namespace Poirot\AuthSystem\Authenticate\Authenticator\IdentityCredentialRepo;

use Poirot\AuthSystem\Authenticate\Exceptions\exAuthentication;
use Poirot\AuthSystem\Authenticate\Interfaces\iAuthAdapter;
use Poirot\AuthSystem\Authenticate\Interfaces\iIdentity;
use Poirot\Std\Struct\aDataOptions;

/**
 * Match Identity Against Options as Credential.
 * 
 * each adapter has individual options to match against identity 
 * record at repository. (some options used as identity credential).
 * 
 * IdentityCredentialRepo may implement some persist storage access
 * like Mongo, DigestFile, mySql, etc. to match user entity.
 * 
 * note: this persist my not fully contains needed user data,
 *       more detail about identity can implemented in Identity instance
 *       or some wrapper around identity like IdentityFulfillmentLazy
 *       to retrieve extra data.
 * 
 * In Most Cases You Must Implement Your Own Adapter!
 * 
 * @method getIdentityMatch($credential = null) @ignore
 */
abstract class aIdentityCredentialAdapter
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
    final function findIdentityMatch()
    {
        if (!$this->isFulfilled())
            throw new \Exception('Adapter Options Not Fulfilled To Retrieve Identity Match.');

        return $this->doFindIdentityMatch(\Poirot\Std\cast($this)->toArray());
    }

    /**
     * Do Match Identity With Given Options/Credential
     *
     * @param array $options Include Credential Data
     *
     * @return iIdentity
     */
    abstract function doFindIdentityMatch(array $options);

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
