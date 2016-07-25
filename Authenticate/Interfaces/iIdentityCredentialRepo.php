<?php
namespace Poirot\AuthSystem\Authenticate\Interfaces;

use Poirot\AuthSystem\Authenticate\Exceptions\exAuthentication;
use Poirot\Std\Interfaces\Struct\iDataOptions;

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
 */
interface iIdentityCredentialRepo
    extends iDataOptions
{
    /**
     * Get Identity Match By Credential as Options
     *
     * @return iIdentity
     * @throws exAuthentication
     * @throws \Exception credential not fulfilled, etc..
     */
    function findIdentityMatch();


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
    
    
    // Credential Options:
    
    // function setUsername();
}
