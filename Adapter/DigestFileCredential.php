<?php
namespace Poirot\Authentication\Adapter;

use Poirot\Authentication\AbstractCredential;

class DigestFileCredential extends AbstractCredential
{
    protected $filename;

    protected $username;

    protected $password;

    protected $realm;

    /**
     * If Authorization was successful identity
     * will use this to fill user data from
     * adapter to identity
     *
     * ! in database it can be a unique field like
     *   mailAddress, pk, ...
     *
     * @return mixed
     */
    function getUserIdentity()
    {
        return $this->getUsername();
    }

    /**
     * @return mixed
     */
    public function getFilename()
    {
        return $this->filename;
    }

    /**
     * @param mixed $filename
     * @return $this
     */
    public function setFilename($filename)
    {
        $this->filename = $filename;

        return $this;
    }

    /**
     * @return mixed
     */
    public function getUsername()
    {
        return $this->username;
    }

    /**
     * @param mixed $username
     * @return $this
     */
    public function setUsername($username)
    {
        $this->username = $username;

        return $this;
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

    /**
     * @return mixed
     */
    public function getRealm()
    {
        return $this->realm;
    }

    /**
     * @param mixed $realm
     * @return $this
     */
    public function setRealm($realm)
    {
        $this->realm = $realm;

        return $this;
    }
}
 