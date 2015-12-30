<?php
namespace Poirot\AuthSystem\Authenticate;

use Poirot\Core\AbstractOptions;
use Poirot\Core\Interfaces\iDataSetConveyor;
use Poirot\Core\Traits\OpenOptionsTrait;

/**
 * Represent User Identity and Data
 *
 */
class BaseIdentity extends AbstractIdentity
{
    use OpenOptionsTrait;

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
}
