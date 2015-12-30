<?php
namespace Poirot\AuthSystem\Authenticate;

use Poirot\AuthSystem\Authenticate\Interfaces\iIdentity;

abstract class AbstractIdentity implements iIdentity
{
    protected $uid;

    /** @var boolean */
    protected $isFullFilled = false;

    /**
     * Construct
     *
     * - set user unique identifier
     *
     * @param string $uid
     */
    function __construct($uid = null)
    {
        if ($uid !== null)
            $this->setUid((string) $uid);
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

    /**
     * Set User Unique Identifier
     *
     * - usually full fill this identity when uid set
     *
     * @param string $uid User Unique ID
     *
     * @return $this
     */
    function setUid($uid)
    {
        $this->uid = $uid;
        $this->isFullFilled = true;
        return $this;
    }

    /**
     * Is Identity Full Filled
     *
     * - full filled mean that all needed data
     *   set for this identity.
     *
     *   ! it's usually is enough to have uid
     *
     * @return boolean
     */
    function isFullFilled()
    {
        return $this->isFullFilled;
    }
}
