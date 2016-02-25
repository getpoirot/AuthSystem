<?php
namespace Poirot\AuthSystem\Authenticate\Identity;

use Poirot\AuthSystem\Authenticate\Interfaces\iIdentityDataProvider;
use Poirot\Std\Interfaces\Struct\iEntityData;

/*
class UserData implements iIdentityDataProvider
{
     # Finds a user by the given user Identity.
     #
     # @param string $property ie. 'user_name'
     # @param mixed $value ie. 'payam@mail.com'
     #
     # @throws \Exception
     # @return EntityInterface
     #
    function findBy($property, $value)
    {
        $entity = new Entity;
        if ($property == 'username' && $value == 'admin')
            ## find by user name
            $entity->from([
                'email' => 'naderi.payam@gmail.com',
                'phone' => '+989354323345'
            ]);

        return $entity;
    }
}

// =================================================================================================================
$lazyLoad = new LazyFulfillmentIdentity(['fulfillment_by' => 'username', 'data_provider' => new UserData]);
$lazyLoad->from(['username' => 'payam']);

kd($lazyLoad->getPhone());
*/

// TODO refactor to new StructData interface

class LazyFulfillmentIdentity extends FulfillmentIdentity
{
    protected $_t_options__internal = [
        // this method will ignore as option in prop
        'getDataProvider',
        'getFulfillmentBy',
        'isFulfilled',
    ];

    /** @var iIdentityDataProvider */
    protected $_data_provider;
    /** @var iEntityData */
    protected $_c__loaded_data;

    /**
     * Set Data Provider Used To Retrieve Identity Data
     * by Fulfillment Property with lazy load
     *
     * @param iIdentityDataProvider $provider
     *
     * @return $this
     */
    function setDataProvider($provider)
    {
        if (!$provider instanceof iIdentityDataProvider)
            throw new \InvalidArgumentException;

        $this->_data_provider = $provider;
        return $this;
    }

    // ...

    /**
     * Clean Identity Data
     *
     * @return void
     */
    function clear()
    {
        foreach($this->props()->writable as $p) {
            if ($p == 'data_provider')
                ## we don`t want to clean setter properties
                continue;

            $this->__unset($p);
        }
    }

    /**
     * Get Options Properties Information
     *
     * @return PropsObject
     */
    function props()
    {
        if (!$this->__isDataLoaded())
            $this->__loadData();

        return parent::props();
    }

    /**
     * @override
     * @inheritdoc
     */
    function __get($key)
    {
        if (!parent::__isset($key) && !$this->__isDataLoaded())
            $this->__loadData();

        return parent::__get($key);
    }

    /**
     * @override
     * @inheritdoc
     */
    function __isset($key)
    {
        if (parent::__isset($key))
            return true;

        if (!$this->__isDataLoaded())
            $this->__loadData();

        return parent::__isset($key);
    }


    protected function __loadData()
    {
        ## avoid recursive fallback on __get below
        $this->_c__loaded_data = true;

        if (!$this->isFulfilled())
            return;

        if (!$this->_data_provider)
            throw new \Exception(
                'Data Provider not exists.'
            );

        $this->_c__loaded_data = $this->_data_provider->findBy(
            $this->__fulfillment_property
            , parent::__get($this->__fulfillment_property)
        );

        $this->from($this->_c__loaded_data);
    }

    protected function __isDataLoaded()
    {
        return ($this->_c__loaded_data) ? true : false;
    }


    function __wakeup()
    {
        ## load data again into memory
        $this->_c__loaded_data = false;
    }
}
