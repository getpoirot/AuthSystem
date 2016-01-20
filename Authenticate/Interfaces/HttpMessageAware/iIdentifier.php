<?php
namespace Poirot\AuthSystem\Authenticate\Interfaces\HttpMessageAware;

use Poirot\Http\Interfaces\Respec\iRequestAware;
use Poirot\Http\Interfaces\Respec\iResponseAware;
use Poirot\Http\Interfaces\Respec\iResponseProvider;

interface iIdentifier extends \Poirot\AuthSystem\Authenticate\Interfaces\iIdentifier
    , iRequestAware
    , iResponseAware
    , iResponseProvider
{

}
