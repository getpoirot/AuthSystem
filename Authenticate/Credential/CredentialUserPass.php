<?php
namespace Poirot\AuthSystem\Authenticate\Credential;

use Poirot\AuthSystem\Authenticate\Interfaces\iCredential;
use Poirot\Std\Struct\aDataOptions;

class CredentialUserPass
    extends aDataOptions
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

        function setEmail($username)
        {
            return $this->setUsername($username);
        }

        function setIdentity($username)
        {
            return $this->setUsername($username);
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

        function setCredential($password)
        {
            return $this->setPassword($password);
        }
    
}
