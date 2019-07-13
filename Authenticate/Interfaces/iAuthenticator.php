<?php
namespace Poirot\AuthSystem\Authenticate\Interfaces;

use Poirot\AuthSystem\Authenticate\Exceptions\AuthenticationError;


Interface iAuthenticator 
{
    /**
     * iAuthenticator constructor.
     *
     * @param iIdentifier $identifier
     */
    function __construct(iIdentifier $identifier);

    /**
     * Authenticate
     *
     * - match credential with Credential Adapter if given
     * 
     * @param iCredential|iIdentityCredentialRepo $credential
     *
     * @return iIdentifier Fulfilled Identifier also
     * @throws AuthenticationError Authentication failed
     */
    function authenticate($credential = null);

    /**
     * Has Authenticated And Identifier Exists
     *
     * - it mean that Identifier has fulfilled
     *
     * @return iIdentifier|false
     */
    function hasAuthenticated();

    /**
     * Identifier Instance
     * 
     * @return iIdentifier
     */
    function identifier();
    
}
