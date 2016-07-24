<?php
namespace Poirot\AuthSystem\Authenticate\Interfaces\HttpMessageAware;

use Poirot\AuthSystem\Authenticate\Interfaces\iIdentifier as iBaseIdentifier;

use Poirot\Http\Interfaces\Respec\iRequestAware;
use Poirot\Http\Interfaces\Respec\iResponseAware;
use Poirot\Http\Interfaces\Respec\iResponseProvider;

interface iIdentifier 
    extends iBaseIdentifier
    , iRequestAware
    , iResponseAware
    , iResponseProvider
{ }
