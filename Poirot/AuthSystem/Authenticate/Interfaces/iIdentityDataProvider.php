<?php
namespace Poirot\AuthSystem\Authenticate\Interfaces;

use Poirot\Core\Interfaces\EntityInterface;

/**
 * Data Model Used Within Identifier/Identity
 * To Retrieve User Data
 *
 * this data model can injected into
 * classes that implemented this feature
 */
interface iIdentityDataProvider
{
    /**
     * Finds a user by the given user Identity.
     *
     * @param string $property  ie. 'user_name'
     * @param mixed  $value     ie. 'payam@mail.com'
     *
     * @throws \Exception
     * @return EntityInterface
     */
    function findBy($property, $value);
}
