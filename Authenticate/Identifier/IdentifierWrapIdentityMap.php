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
        $identity     = clone $this->identity_map;
        $wrapIdentity = $this->identifier->withIdentity();

        try {
            $identity->import($wrapIdentity);
            $identity->import(['_identity' => $wrapIdentity]); // also have origin identity

        } catch (\Exception $e) {
            // identity may change so clear it
            throw new \RuntimeException(sprintf(
                'Previous Data Stored In Session cant import to Identifier (%s); Err: (%s).'
                , get_class($identity), $e->getMessage()
            ));
        }


        return $identity;
    }
}
