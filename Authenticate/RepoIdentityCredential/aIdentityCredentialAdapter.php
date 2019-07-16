<?php
namespace Poirot\AuthSystem\Authenticate\RepoIdentityCredential;

use Poirot\Std\Exceptions\UnexpectedInputValueError;
use Poirot\Std\Struct\DataOptionsOpen;
use Poirot\AuthSystem\Authenticate\Identifier\aIdentifier;
use Poirot\AuthSystem\Authenticate\Interfaces\iIdentityCredentialRepo;
use Poirot\AuthSystem\Authenticate\Interfaces\iIdentity;

/*
$adapter = new IdentityCredentialDigestFile();
$match   = $adapter
    ->setUsername('admin')
    ->setPassword('123456')
    ->findIdentityMatch();

if (!$match)
    throw new P\AuthSystem\Authenticate\Exceptions\exWrongCredential();

echo "Hello {$match->getUsername()}.";
*/

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
abstract class aIdentityCredentialAdapter
    extends DataOptionsOpen
    implements iIdentityCredentialRepo
{
    const DEFAULT_REALM = aIdentifier::DEFAULT_REALM;

    protected $realm;


    /**
     * Get Identity Match By Credential as Options
     *
     * @return iIdentity|false
     * @throws \Exception credential not fulfilled
     */
    final function findIdentityMatch()
    {
        if (!$this->isFulfilled())
            return false;
            /*throw new \Exception(sprintf(
                'Credential Adapter Options Not Fulfilled By Given Options: (%s).'
                , serialize(\Poirot\Std\cast($this)->toArray())
            ));*/

        $credential = \Poirot\Std\cast($this)->toArray();
        return $this->doFindIdentityMatch($credential);
    }

    /**
     * Do Match Identity With Given Options/Credential
     *
     * @param array $credentials Include Credential Data
     *
     * @return iIdentity|false
     * @throws UnexpectedInputValueError
     */
    abstract protected function doFindIdentityMatch(array $credentials);

    
    // ...

    /**
     * Set Realm
     * @param string $realm
     * @return $this
     */
    function setRealm($realm)
    {
        $this->realm = (string) $realm;
        return $this;
    }

    /**
     * Get Realm
     * @required
     * @return string
     */
    function getRealm()
    {
        if (!$this->realm)
            $this->setRealm(self::DEFAULT_REALM);

        return $this->realm;
    }
}
