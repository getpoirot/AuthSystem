<?php
namespace Poirot\AuthSystem\Authenticate;

use Poirot\AuthSystem\Authenticate\Interfaces\iCredential;
use Poirot\Core\Traits\OpenOptionsTrait;

abstract class AbstractCredential implements iCredential
{
    use OpenOptionsTrait;
}
