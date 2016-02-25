<?php
namespace Poirot\AuthSystem\Authenticate;

use Poirot\AuthSystem\Authenticate\Interfaces\iCredential;
use Poirot\Std\Struct\OpenOptionsData;

abstract class AbstractCredential extends OpenOptionsData
    implements iCredential
{

}
