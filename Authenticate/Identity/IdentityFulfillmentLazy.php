<?php
namespace Poirot\AuthSystem\Authenticate\Identity;

use Poirot\AuthSystem\Authenticate\Exceptions\exLoadUserFailed;
use Poirot\AuthSystem\Authenticate\Interfaces\iProviderIdentityData;
use Poirot\Std\Interfaces\Struct\iData;

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
$lazyLoad->import(['username' => 'payam']);

// WHEN Identity is fulfillment we can retrieve extra data 
// provided by data_provider and imported to identity at runtime lazy!

kd($lazyLoad->getPhone());
*/

class IdentityFulfillmentLazy
    extends IdentityFulfillment
{
    /** @var iProviderIdentityData */
    protected $_data_provider;
    /** @var iData */
    protected $_c__loaded_data;


    /**
     * AbstractStruct constructor.
     *
     * @param iProviderIdentityData   $provider
     * @param string                  $fulfillmentProp Find entity data this property from provider
     * @param null|array|\Traversable $data
     */
    function __construct(iProviderIdentityData $provider, $fulfillmentProp, $data = null)
    {
        parent::__construct($fulfillmentProp, $data);
        $this->setDataProvider($provider);
    }

    /**
     * @ignore
     * 
     * Set Data Provider Used To Retrieve Identity Data
     * by Fulfillment Property with lazy load
     *
     * @param iProviderIdentityData $provider
     *
     * @return $this
     */
    function setDataProvider(iProviderIdentityData $provider)
    {
        $this->_data_provider = $provider;
        return $this;
    }

    /**
     * Empty from all values
     * @return $this
     */
    function clean()
    {
        parent::clean();

        $this->_c__loaded_data = false;
        return $this;
    }

    // ...

    /**
     * Get Options Properties Information
     *
     */
    protected function _getProperties()
    {
        if (!$this->_isDataLoaded())
            // load data to represent all properties
            $this->_loadData();

        return parent::_getProperties();
    }

    /**
     * @override
     * @inheritdoc
     */
    function __get($key)
    {
        if (!parent::__isset($key) && !$this->_isDataLoaded())
            $this->_loadData();

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

        if (!$this->_isDataLoaded())
            $this->_loadData();

        return parent::__isset($key);
    }


    protected function _loadData()
    {
        ## avoid recursive fallback on __get below
        $this->_c__loaded_data = true;

        if (!$this->isFulfilled())
            return;

        if (!$this->_data_provider)
            throw new \Exception('Data Provider not defined.');

        $userData = $this->_data_provider->findOneMatchBy(
            $this->fulfillment_property
            , parent::__get($this->fulfillment_property)
        );
        if (false === $userData || null === $userData)
            throw new exLoadUserFailed(sprintf(
                'Failed To Loaded User Data'
            ));

        $this->_c__loaded_data = $userData;
        $this->import($this->_c__loaded_data);
    }

    protected function _isDataLoaded()
    {
        return ($this->_c__loaded_data) ? true : false;
    }

    
    // ...

    function __wakeup()
    {
        ## load data again into memory
        $this->_c__loaded_data = false;
    }
}
