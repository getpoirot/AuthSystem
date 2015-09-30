<?php
namespace Poirot\AuthSystem\Authenticate;

use Poirot\AuthSystem\Authenticate\Interfaces\iIdentity;
use Poirot\Core\AbstractOptions;
use Poirot\Core\Interfaces\iDataSetConveyor;
use Poirot\Core\Traits\OptionsTrait;

class BaseIdentity implements iIdentity
{
    use OptionsTrait;

    protected $uid;

    /**
     * Construct
     *
     * - set user unique identifier
     *
     * @param string                 $uid
     * @param array|iDataSetConveyor $options
     */
    function __construct($uid, $options = null)
    {
        if ($options !== null)
            $this->from($options);

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
