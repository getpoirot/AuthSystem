<?php
namespace Poirot\AuthSystem\Authenticate\RepoIdentityCredential;

use Poirot\AuthSystem\Authenticate\Exceptions\exAuthentication;
use Poirot\AuthSystem\Authenticate\Interfaces\iIdentity;
use Poirot\AuthSystem\Authenticate\Interfaces\iIdentityCredentialRepo;

class IdentityCredentialWrap 
    implements iIdentityCredentialRepo
{
    /** @var iIdentityCredentialRepo */
    protected $wrap;

    
    /**
     * Construct
     * 
     * @param iIdentityCredentialRepo $repoWrap Wrapped iIdentityCredentialRepo
     */
    function __construct(iIdentityCredentialRepo $repoWrap)
    {
        $this->wrap = $repoWrap;
    }

    /**
     * Get Identity Match By Credential as Options
     *
     * @return iIdentity
     * @throws exAuthentication
     * @throws \Exception credential not fulfilled, etc..
     */
    function findIdentityMatch()
    {
        return $this->wrap->findIdentityMatch();
    }
    
    /**
     * Is Required Property Full Filled?
     *
     * - with no property it will check for whole properties
     *
     * @param null|string $property_key
     *
     * @return boolean
     */
    function isFulfilled($property_key = null)
    {
        return $this->wrap->isFulfilled($property_key);
    }
    
    /**
     * Set Realm
     * @param string $realm
     * @return $this
     */
    function setRealm($realm)
    {
        $this->wrap->setRealm($realm);
        return $this;
    }

    /**
     * Get Realm
     * @return string|null
     */
    function getRealm()
    {
        return $this->wrap->getRealm();
    }

    /**
     * Retrieve an external iterator
     * @link http://php.net/manual/en/iteratoraggregate.getiterator.php
     * @return \Traversable An instance of an object implementing <b>Iterator</b> or
     * <b>Traversable</b>
     * @since 5.0.0
     */
    public function getIterator()
    {
        return $this->wrap->getIterator();
    }

    /**
     * Count elements of an object
     * @link http://php.net/manual/en/countable.count.php
     * @return int The custom count as an integer.
     * </p>
     * <p>
     * The return value is cast to an integer.
     * @since 5.1.0
     */
    public function count()
    {
        return $this->wrap->count();
    }

    /**
     * Set Struct Data From Array
     *
     * @param array|\Traversable|null $data
     *
     * @throws \InvalidArgumentException
     * @return $this
     */
    function import($data)
    {
        $this->wrap->import($data);
        return $this;
    }

    /**
     * Empty from all values
     * @return $this
     */
    function clean()
    {
        $this->wrap->clean();
        return $this;
    }

    /**
     * Is Empty?
     * @return bool
     */
    function isEmpty()
    {
        return $this->wrap->isEmpty();
    }

    /**
     * NULL value for a property considered __isset false
     * @param mixed $key
     * @return bool
     */
    function has($key)
    {
        return $this->wrap->has($key);
    }

    /**
     * NULL value for a property considered __isset false
     * @param mixed $key
     * @return $this
     */
    function del($key)
    {
        $this->wrap->del($key);
        return $this;
    }
}
