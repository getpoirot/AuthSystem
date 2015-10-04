<?php
namespace Poirot\AuthSystem\Authenticate;

use Poirot\Core\AbstractOptions;
use Poirot\Core\Traits\OptionsTrait;

class BaseIdentity extends AbstractIdentity
{
    use OptionsTrait;

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
        parent::__construct($uid);

        if ($options !== null)
            $this->from($options);
    }

}
