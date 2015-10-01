<?php
namespace Poirot\AuthSystem\Authenticate\Interfaces;

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
