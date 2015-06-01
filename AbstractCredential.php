<?php
namespace Poirot\AuthSystem;

use Poirot\AuthSystem\Authenticate\Interfaces\iCredential;
use Poirot\Core\AbstractOptions;

abstract class AbstractCredential extends AbstractOptions
    implements
    iCredential
{

}
 