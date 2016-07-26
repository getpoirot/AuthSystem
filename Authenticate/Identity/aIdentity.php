<?php
namespace Poirot\AuthSystem\Authenticate\Identity;

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
 * Note: Identity Objects May Serialize Into Persist Storage
 *       like Session, Be aware of object serialization.
 *       __sleep(), __wakeup(), .... 
 * 
 * @method isFulfilled($property_key = null) @ignore
 */
abstract class aIdentity
    extends DataOptionsOpen
    implements iIdentity
{
    
}
