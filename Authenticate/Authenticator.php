<?php
namespace Poirot\AuthSystem\Authenticate;

use Poirot\AuthSystem\Authenticate\Exceptions\exAuthentication;
use Poirot\AuthSystem\Authenticate\Exceptions\exNotAuthenticated;
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
     * // TODO identityMap can removed and apply on first param combined with identifier 
     * // new IdentifierWrapIdentityMap($identifier, $identityMap);
     * 
     * iAuthenticator constructor.
     *
     * @param iIdentifier             $identifier
     * @param iIdentityCredentialRepo $adapter     Identity Credential repository
     * @param iIdentity               $identityMap Default identity to map lazy load extra data
     */
    function __construct(iIdentifier $identifier, iIdentityCredentialRepo $adapter = null, iIdentity $identityMap = null)
    {
        if ($identityMap)
            $identifier = new IdentifierWrapIdentityMap($identifier, $identityMap);
        $this->identifier = $identifier;
        
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
        if ($credential instanceof iIdentity) {
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

        $identifier = $this->identifier();
        $identifier->exactIdentity($identity);
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
        try {
            // if identifier cant detect identity and identity not set manually-
            // it will rise exception
            if (!$this->identifier()->withIdentity()->isFulfilled())
                return false;
        } catch (exNotAuthenticated $e) {
            return false;
        }
            
        return $this->identifier();
    }

    /**
     * Identifier Instance
     *
     * @return iIdentifier
     */
    function identifier()
    {
        return $this->identifier;
    }
}
