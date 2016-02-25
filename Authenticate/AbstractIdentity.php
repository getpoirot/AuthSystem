<?php
namespace Poirot\AuthSystem\Authenticate;

use Poirot\AuthSystem\Authenticate\Interfaces\iIdentity;
use Poirot\Std\Struct\OpenOptionsData;

abstract class AbstractIdentity extends OpenOptionsData
    implements iIdentity
{
    protected $_t_options__internal = [
        'isFulfilled',
    ];
}
