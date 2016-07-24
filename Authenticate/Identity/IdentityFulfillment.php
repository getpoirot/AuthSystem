<?php
namespace Poirot\AuthSystem\Authenticate\Identity;

use Poirot\AuthSystem\Authenticate\aIdentity;

/*
## this mean authenticator need at least username to satisfy by identifier
new Authenticator(['identity' => new IdentityFulfillment(['fulfillment_by' => 'username'])]);
*/

class IdentityFulfillment 
    extends aIdentity
{
    /** @var string 'property_underscore_format' */
    protected $fulfillment_property;

    /**
     * @ignore 
     * 
     * Set Fulfillment Property
     *
     * ! this property must set available to fulfillment
     *
     * @param string $property
     *
     * @return $this
     */
    function setFulfillmentBy($property)
    {
        $this->fulfillment_property = \Poirot\Std\cast((string)$property)->under_score();
        return $this;
    }

    /**
     * Is Identity Full Filled?
     *
     * - full filled mean that all needed data
     *   set for this identity.
     * - with no property it will check for whole properties
     *
     * @param null|string $property_key
     *
     * @return boolean
     */
    function isFulfilled($property_key = null)
    {
        if ($property_key) {
            $result = parent::isFulfilled($property_key);
        } else {
            // Fulfillment by specific property
            $result = ( self::__isset($this->fulfillment_property) && self::__get($this->fulfillment_property) )
                ? true : false;
            
            $result = $result && parent::isFulfilled();
        }
        
        return $result;
    }
}
