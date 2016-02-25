<?php
namespace Poirot\AuthSystem\Authenticate\Credential;

use Poirot\AuthSystem\Authenticate\AbstractIdentity;
use Poirot\AuthSystem\Authenticate\Interfaces\iCredentialHttpAware;
use Poirot\Http\Interfaces\Message\iHttpRequest;
use Poirot\Http\Message\HttpRequest;

class UserPassCredential extends AbstractIdentity
    implements iCredentialHttpAware
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


    /**
     * Set Options From Request Http Object
     *
     *  ie. extract user/pass from post data
     *
     * @param iHttpRequest $request
     *
     * @throws \Exception
     * @return $this
     */
    function fromRequest(iHttpRequest $request)
    {
        if (!$request instanceof HttpRequest)
            $request = new HttpRequest($request);

        if (!$request->plg()->methodType()->isPost())
            return $this;


        // TODO define post value map request
        $POST = $request->plg()->phpServer()->getPost()->toArray();
        $this->from($POST);

        return $this;
    }
}
