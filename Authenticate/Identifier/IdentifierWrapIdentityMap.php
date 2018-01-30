<?php
namespace Poirot\AuthSystem\Authenticate\Identifier;

use Poirot\AuthSystem\Authenticate\Interfaces\iIdentifier;
use Poirot\AuthSystem\Authenticate\Interfaces\iIdentity;


/**
 * Used To Change Default Identity of Identifier
 * Usually when we need some extra data against default identifier
 * filled entity.
 */
class IdentifierWrapIdentityMap 
    extends IdentifierWrap
{
    /** @var iIdentity */
    protected $identity_map;


    /**
     * IdentifierWrapIdentityMap constructor.
     *
     * @param iIdentifier $identifier Wrapped Identifier
     * @param iIdentity   $identity   Default identity to map lazy load extra data
     */
    function __construct(iIdentifier $identifier, iIdentity $identity)
    {
        $this->identity_map = $identity;
        parent::__construct($identifier);
    }

    /**
     * Get Authenticated User Data Copy
     *
     * - for check that user is signIn the identity must
     *   fulfilled.
     * - if canRecognizeIdentity extract data from it
     *   this cause identity fulfillment with given data
     *   ie. when user exists in session build identity from that
     *
     * @return iIdentity
     */
    function withIdentity()
    {
        // TODO improved if we use Identity Map To Lazy Get Data
        $identity = clone $this->identity_map;
        $identity->import($this->identifier->withIdentity());
        $identity->import(['_identity' => $this->identifier->withIdentity()]); // also have origin identity
        return $identity;
    }
}
