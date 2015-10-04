<?php
namespace Poirot\AuthSystem\Authenticate\Adapter;

use Poirot\AuthSystem\Authenticate\Interfaces\iCredential;
use Poirot\Core\Traits\OptionsTrait;

class UserPassCredential implements iCredential
{

    use OptionsTrait;

    protected $password;
    protected $email;

    /**
     * @return mixed
     */
    public function getEmail()
    {
        return $this->email;
    }

    /**
     * @param mixed $email
     */
    public function setEmail($email)
    {
        $this->email = $email;
    }


    function __construct($options=null)
    {

    }
    /**
     * @return mixed
     */
    public function getPassword()
    {
        return $this->password;
    }

    /**
     * @param mixed $password
     * @return $this
     */
    public function setPassword($password)
    {
        $this->password = $password;

        return $this;
    }

}
 