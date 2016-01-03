<?php
namespace Poirot\AuthSystem\Authenticate\Identity;

use Poirot\AuthSystem\Authenticate\AbstractIdentity;
use Poirot\Core\AbstractOptions;

/**
 * Represent User Identity and Data
 *
 */
class FulfillmentIdentity extends AbstractIdentity
{
    protected $uid;

    /**
     * Get user unique identifier
     *
     * @return string|null
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
     * @param string|null $uid User Unique ID
     *
     * @return $this
     */
    function setUid($uid)
    {
        $this->uid = $uid;
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
    function isFulfilled()
    {
        return ($this->getUid()) ? true : false;
    }
}
