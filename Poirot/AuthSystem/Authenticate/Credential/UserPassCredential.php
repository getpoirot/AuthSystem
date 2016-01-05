<?php
namespace Poirot\AuthSystem\Authenticate\Credential;

use Poirot\AuthSystem\Authenticate\Interfaces\iCredential;
use Poirot\Core\AbstractOptions;

class UserPassCredential extends AbstractOptions
    implements iCredential
{
    protected $username;
    protected $password;

    /**
     * @return string
     */
    public function getUsername()
    {
        return $this->username;
    }

    /**
     * @param string $username
     * @return $this
     */
    public function setUsername($username)
    {
        $this->username = $username;
        return $this;
    }

    /**
     * @return string
     */
    public function getPassword()
    {
        return $this->password;
    }

    /**
     * @param string $password
     * @return $this
     */
    public function setPassword($password)
    {
        $this->password = $password;
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
        return ($this->getUsername() !== null && $this->getPassword() !== null);
    }

    /**
     * Clean Identity Data
     *
     * @return void
     */
    function clean()
    {
        $this->__unset('username');
        $this->__unset('password');
    }
}
