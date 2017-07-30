<?php
namespace Poirot\AuthSystem\Authenticate\IdentityProvider;

use Poirot\AuthSystem\Authenticate\Identity\IdentityFulfillmentLazy;
use Poirot\AuthSystem\Authenticate\Interfaces\iProviderIdentityData;
use Poirot\Std\Interfaces\Struct\iData;

class ProviderNothing
    implements iProviderIdentityData
{
    /**
     * Finds a user by the given user Identity.
     *
     * @param string $property ie. 'name'
     * @param mixed $value ie. 'payam@mail.com'
     *
     * @return iData
     * @throws \Exception
     */
    function findOneMatchBy($property, $value)
    {
        // Return empty data; will ::import into IdentityFulfillment
        /** @see IdentityFulfillmentLazy */
        return [];
    }
}
