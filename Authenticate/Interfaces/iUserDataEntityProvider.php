<?php
namespace Poirot\AuthSystem\Interfaces;

use Poirot\Core\Entity;
use Poirot\AuthSystem\Authorize\Exceptions\UserNotFoundException;

/**
 * Data Model Used Within Authorize Services
 * To Retrieve User Data Into Identity
 *
 * this data model can injected into
 * iAuthorizeUserDataAware implemented classes
 *
 */
interface iUserDataEntityProvider
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
