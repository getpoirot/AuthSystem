<?php
namespace Poirot\AuthSystem\Authenticate\RepoIdentityCredential;

use Poirot\AuthSystem\Authenticate\Exceptions\exAuthentication;
use Poirot\AuthSystem\Authenticate\Interfaces\iIdentity;
use Poirot\AuthSystem\Authenticate\Interfaces\iIdentityCredentialRepo;

/**
 * Used To Change Default Identity of Repo Match Result
 * Usually when we need some extra data against default matched
 * filled entity.
 */
class IdentityCredentialWrapIdentityMap 
    extends IdentityCredentialWrap
{
    /** @var iIdentity */
    protected $identity_map;
    
    /**
     * Construct
     * 
     * @param iIdentityCredentialRepo $repoWrap    Wrapped iIdentityCredentialRepo
     * @param iIdentity               $identityMap Default identity to map lazy load extra data
     */
    function __construct(iIdentityCredentialRepo $repoWrap, iIdentity $identityMap)
    {
        $this->identity_map = clone $identityMap;
        parent::__construct($repoWrap);
        
    }

    /**
     * Get Identity Match By Credential as Options
     *
     * @return iIdentity
     * @throws exAuthentication
     * @throws \Exception credential not fulfilled, etc..
     */
    function findIdentityMatch()
    {
        $identity = $this->wrap->findIdentityMatch();
        if (!$identity)
            return false;
        
        $return   = $this->identity_map->clean();
        $return->import($identity);
        return $identity;
    }
}
