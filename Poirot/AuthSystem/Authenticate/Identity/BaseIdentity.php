<?php
namespace Poirot\AuthSystem\Authenticate\Identity;

use Poirot\AuthSystem\Authenticate\AbstractIdentity;
use Poirot\Core\AbstractOptions;
use Poirot\Core\Interfaces\iDataSetConveyor;

/**
 * Represent User Identity and Data
 *
 */
class BaseIdentity extends AbstractIdentity
{
    protected $uid;

    /**
     * Construct
     *
     * - set user unique identifier
     *
     * @param string|null|array      $uid
     * @param array|iDataSetConveyor $options Extra User Data
     */
    function __construct($uid = null, $options = null)
    {
        if (is_array($uid) || $uid instanceof iDataSetConveyor)
            ## options as array or dataSet
            $options = $uid;
        else
            parent::__construct($uid);

        if ($options !== null)
            $this->from($options);
    }

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
    function isFullFilled()
    {
        return ($this->getUid()) ? true : false;
    }
}
