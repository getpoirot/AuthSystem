<?php
namespace Poirot\AuthSystem\Authenticate\Identity;

class IdentityHttpDigest
    extends aIdentity
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
        $a1hash = (string) $a1hash;
        if (strlen($a1hash) !== 32)
            // MD5 hash error
            throw new \InvalidArgumentException(sprintf('The A1 Hash (%s) seems is invalid.', $a1hash));
        
        $this->hash = $a1hash;
        return $this;
    }

        function setA1($a1hash)
        {
            return $this->setHash($a1hash);
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
            $result = ($this->getUsername() !== null && $this->getHash() !== null);
            $result = $result && parent::isFulfilled();
        }

        return $result;
    }
}
