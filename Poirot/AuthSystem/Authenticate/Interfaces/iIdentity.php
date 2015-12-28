<?php
namespace Poirot\AuthSystem\Authenticate\Interfaces;

/**
 * Represent User Identity and Data
 *
 * [code:]
 *   $identity->getUid();
 *   $identity->getUserEmail(); # extra related data
 * [code]
 *
 */
interface iIdentity
{
    /**
     * Construct
     * Set user unique identifier
     *
     * @param string $uid
     */
    function __construct($uid);

    /**
     * Get user unique identifier
     *
     * @return string
     */
    function getUid();
}
