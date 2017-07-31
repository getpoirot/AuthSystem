<?php
namespace Poirot\AuthSystem\Authenticate;

use Poirot\AuthSystem\Authenticate\Exceptions\exAuthentication;
use Poirot\AuthSystem\Authenticate\Exceptions\exLoadUserFailed;
use Poirot\AuthSystem\Authenticate\Exceptions\exNotAuthenticated;
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
    protected $repoIdentityCredential;


    /**
     * iAuthenticator constructor.
     *
     * @param iIdentifier             $identifier
     * @param iIdentityCredentialRepo $adapter     Identity Credential repository
     */
    function __construct(iIdentifier $identifier, iIdentityCredentialRepo $adapter = null)
    {
        $this->identifier = $identifier;
        $this->repoIdentityCredential = $adapter;
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
        if ($this->repoIdentityCredential === null)
            throw new \InvalidArgumentException('Identity Credential Adapter Required.');


        if ($credential instanceof iIdentity) {
            $identity = $credential;
            goto f_authenticate_done;
        }

        $repoCredential = $credential;
        if (! $repoCredential instanceof iIdentityCredentialRepo ) {
            $repoCredential = $this->repoIdentityCredential;
        } else {
            $credential = null;
        }

        if (! ($credential instanceof \Traversable || is_array($credential)) )
            throw new \InvalidArgumentException(sprintf(
                'Credential must instanceof iCredential(\Traversbale) or Array; given: (%s).'
                , \Poirot\Std\flatten($credential)
            ));

        $repoCredential->import($credential);
        if (!$repoCredential->isFulfilled())
            throw new \Exception(sprintf(
                'These credential (%s) not fulfillment the CredentialRepo(%s).'
                , \Poirot\Std\flatten($credential), \Poirot\Std\flatten($repoCredential)
            ));

        $identity = $repoCredential->findIdentityMatch();


f_authenticate_done:

        if ( !$identity instanceof iIdentity || ($identity instanceof iIdentity && !$identity->isFulfilled()) )
            throw new exAuthentication;

        $identifier = $this->identifier();
        $identifier->giveIdentity($identity);
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
        } catch (exLoadUserFailed $e) {
            // User not found any more !!
            // clear from identity storage (session/cookie)
            $this->identifier()->signOut();
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
