<?php
namespace Poirot\AuthSystem\Authenticate;

use Poirot\AuthSystem\Authenticate\Interfaces\iIdentity;

abstract class AbstractIdentity implements iIdentity
{
    protected $uid;

    /**
     * Construct
     *
     * - set user unique identifier
     *
     * @param string $uid
     */
    function __construct($uid)
    {
        $this->uid = (string) $uid;
    }

    /**
     * Get user unique identifier
     *
     * @return string
     */
    function getUid()
    {
        return $this->uid;
    }
}
