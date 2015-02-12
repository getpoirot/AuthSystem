<?php
namespace Poirot\Authentication\Interfaces;

use Poirot\Core\Entity;
use Poirot\Authentication\Authorize\Exceptions\UserNotFoundException;

/**
 * Data Model Used Within Authorize Services
 * To Retrieve User Data Into Identity
 *
 * this data model can injected into
 * iAuthorizeUserDataAware implemented classes
 *
 */
interface iUserDataModelProvider
{
    /**
     * Finds a user by the given user Identity.
     *
     * @param mixed $identity
     *
     * @throws UserNotFoundException
     * @return Entity
     */
    function findByIdentity($identity);
}
