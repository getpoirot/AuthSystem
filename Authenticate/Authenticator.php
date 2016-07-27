<?php
namespace Poirot\AuthSystem\Authenticate;

use Poirot\AuthSystem\Authenticate\Exceptions\exAuthentication;
use Poirot\AuthSystem\Authenticate\Exceptions\exWrongCredential;
use Poirot\AuthSystem\Authenticate\Identifier\IdentifierWrapIdentityMap;
use Poirot\AuthSystem\Authenticate\Interfaces\iCredential;
use Poirot\AuthSystem\Authenticate\Interfaces\iIdentifier;
use Poirot\AuthSystem\Authenticate\Interfaces\iIdentityCredentialRepo;
use Poirot\AuthSystem\Authenticate\Interfaces\iAuthenticator;
use Poirot\AuthSystem\Authenticate\Interfaces\iIdentity;

class Authenticator
    implements iAuthenticator
{
    /** @var iIdentifier */
    protected $identifier;
    /** @var iIdentityCredentialRepo */
    protected $identityCredential;


    /**
     * iAuthenticator constructor.
     *
     * @param iIdentifier             $identifier
     * @param iIdentityCredentialRepo $adapter     Identity Credential repository
     * @param iIdentity               $identityMap Default identity to map lazy load extra data
     */
    function __construct(iIdentifier $identifier, iIdentityCredentialRepo $adapter = null, iIdentity $identityMap = null)
    {
        $this->identifier = new IdentifierWrapIdentityMap($identifier, $identityMap);

        if ($adapter === null)
            throw new \InvalidArgumentException('Identity Credential Adapter Required.');

        $this->identityCredential = $adapter;
    }

    /**
     * Authenticate
     * 
     * !! Consider that current identifier identity may be filled with some data
     *    so this must cleaned.
     * 
     * !! Usually you must signIn Authenticated Identifier Manually
     *    [code:]
     *       $identifier = $auth->authenticate();
     *       $identifier->signIn();
     *    [code]
     * 
     * @param array|\Traversable|iCredential| iIdentityCredentialRepo| iIdentity $credential
     *
     * @return iIdentifier Fulfilled Identifier also
     * @throws exAuthentication|\Exception
     */
    function authenticate($credential = null)
    {
        if ($credential instanceof iIdentity)
        {
            $identity = $credential;
            goto f_authenticate_done;
        }

        $credentialRepo = $credential;
        if (!$credentialRepo instanceof iIdentityCredentialRepo) {
            $credentialRepo = $this->identityCredential;
        } else {
            $credential = null;
        }

        if (!($credential instanceof \Traversable || is_array($credential)))
            throw new \InvalidArgumentException(sprintf(
                'Credential must instanceof iCredential(\Traversbale) or Array; given: (%s).'
                , \Poirot\Std\flatten($credential)
            ));

        $credentialRepo->import($credential);
        if (!$credentialRepo->isFulfilled())
            throw new \Exception(sprintf(
                'These credential (%s) not fulfillment the CredentialRepo(%s).'
                , \Poirot\Std\flatten($credential), \Poirot\Std\flatten($credentialRepo)
            ));

        $identity = $credentialRepo->findIdentityMatch();


f_authenticate_done:

        if (!$identity instanceof iIdentity || ($identity instanceof iIdentity && !$identity->isFulfilled()))
            throw new exAuthentication;


        $identifier = clone $this->identifier;
        $identifier->identity()->clean()->import($identity);
        if (!$identifier->identity()->isFulfilled())
            throw new \Exception(sprintf(
                'Given Identity By IdentityCredential Repo Not Fulfilled Authentication Identity (%s).'
                , \Poirot\Std\flatten($this->identifier->identity())
            ));

        return $identifier;
    }

    /**
     * Has Authenticated And Identifier Exists
     *
     * - it mean that Identifier identity has fulfilled
     *   otherwise return false
     *
     * @return iIdentifier|false
     */
    function hasAuthenticated()
    {
        if (!$this->identifier->identity()->isFulfilled())
            return false;
        
        return $this->identifier;
    }
}
