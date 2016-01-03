<?php
namespace Poirot\AuthSystem\Authenticate\Identity;

use Poirot\AuthSystem\Authenticate\Interfaces\iIdentityDataProvider;
use Poirot\Core\AbstractOptions\PropsObject;
use Poirot\Core\Interfaces\EntityInterface;

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
        return new Entity([
            'email' => 'naderi.payam@gmail.com',
            'phone' => '+989354323345'
        ]);
    }
}

// =================================================================================================================
$lazyLoad = new LazyFulfillmentIdentity(['fulfillment_by' => 'username', 'data_provider' => new UserData]);
$lazyLoad->from(['username' => 'payam']);

kd($lazyLoad->getPhone());
*/

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
    /** @var EntityInterface */
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
    function clean()
    {
        foreach($this->props()->writable as $p) {
            if ($p == 'data_provider')
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
        if (!$this->__isDataLoaded())
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
            throw new \Exception(sprintf(
                'We can`t access extra data, because identity not fulfilled on property (%s) Yet.'
                , $this->__fulfillment_property
            ));

        if (!$this->_data_provider)
            throw new \Exception(
                'Data Provider not exists.'
            );

        $this->_c__loaded_data = $this->_data_provider->findBy(
            $this->__fulfillment_property
            , $this->__get($this->__fulfillment_property)
        );

        $this->from($this->_c__loaded_data);
    }

    protected function __isDataLoaded()
    {
        return ($this->_c__loaded_data !== null) ? true : false;
    }

    function __wakeup()
    {
        $this->_c__loaded_data = false;
    }
}
