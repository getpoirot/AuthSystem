<?php
namespace Poirot\AuthSystem\Authenticate\Identity;

use Poirot\AuthSystem\Authenticate\AbstractIdentity;
use Poirot\Core\AbstractOptions;

/*
## this mean authenticator need at least username to satisfy by identifier
new Authenticator(['identity' => new FulfillmentIdentity(['fulfillment_by' => 'username'])]);
*/

class FulfillmentIdentity extends AbstractIdentity
{
    protected $_t_options__internal = [
        // this method will ignore as option in prop
        'getFulfillmentBy',
        'isFulfilled',
    ];

    /** @var string 'property_underscore_format' */
    protected $__fulfillment_property;

    /**
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
        $this->__fulfillment_property = \Poirot\Core\sanitize_underscore($property);
        return $this;
    }

    /**
     * Is Identity Full Filled
     *
     * - full filled mean that all needed data
     *   set for this identity.
     *
     * @return boolean
     */
    function isFulfilled()
    {
        return ($this->__isset($this->__fulfillment_property) && $this->__get($this->__fulfillment_property))
            ? true : false;
    }
}
