<?php
namespace Poirot\AuthSystem\Authenticate\Interfaces;

use Poirot\AuthSystem\Authenticate\Exceptions\UserNotFoundException;
use Poirot\Core\Entity;

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
     * @return mixed
     */
    function findByIdentity($identity);
}
