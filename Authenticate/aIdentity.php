<?php
namespace Poirot\AuthSystem\Authenticate;

use Poirot\AuthSystem\Authenticate\Interfaces\iIdentity;
use Poirot\Std\Struct\DataOptionsOpen;


/**
 * Usually Most Identity Must Implement isFulfilled Method
 * 
 * Represent User Identity and Data
 *
 * [code:]
 *   $identity->getUid();
 *   $identity->getUserEmail(); # extra related data
 * [code]
 *
 * @method isFulfilled($property_key = null) @ignore
 */
abstract class aIdentity
    extends DataOptionsOpen
    implements iIdentity
{
    
}
