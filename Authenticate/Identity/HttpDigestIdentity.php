<?php
namespace Poirot\AuthSystem\Authenticate\Identity;

use Poirot\AuthSystem\Authenticate\AbstractIdentity;

class HttpDigestIdentity extends AbstractIdentity
{
    protected $username;
    protected $hash;     ## A1 = md5(username:realm:password)

    /**
     * @return mixed
     */
    public function getUsername()
    {
        return $this->username;
    }

    /**
     * @param mixed $username
     */
    public function setUsername($username)
    {
        $this->username = $username;
    }

    /**
     * @return string
     */
    public function getHash()
    {
        return $this->hash;
    }

        function getA1()
        {
            return $this->getHash();
        }

    /**
     * @param string $a1hash
     * @return $this
     */
    public function setHash($a1hash)
    {
        $this->hash = $a1hash;
        return $this;
    }

        function setA1($a1hash)
        {
            return $this->setHash($a1hash);
        }

    /**
     * Is Identity Full Filled
     *
     * - full filled mean that all needed data
     *   set for this identity.
     *
     * @return boolean
     */
    function isFulfilled($key = null)
    {
        // TODO implement check for specific key property fulfillment

        return ($this->getUsername() !== null && $this->getHash() !== null);
    }
}
