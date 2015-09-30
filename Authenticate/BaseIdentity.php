<?php
namespace Poirot\AuthSystem\Authenticate;

use Poirot\AuthSystem\Authenticate\Interfaces\iIdentity;
use Poirot\Core\AbstractOptions;
use Poirot\Core\Interfaces\iDataSetConveyor;

class BaseIdentity extends AbstractOptions
    implements iIdentity
{
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
        parent::__construct($options);

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
