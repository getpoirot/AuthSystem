<?php
namespace Poirot\Authentication\Adapter;

use Poirot\Authentication\AbstractIdentity;
use Poirot\Authentication\Authorize\Exceptions\WrongCredentialException;
use Poirot\Authentication\Interfaces\iAuthorize;
use Poirot\Authentication\Interfaces\iIdentity;
use Poirot\Core\AbstractOptions;
use Poirot\Storage\Adapter\SessionStorage;

class DigestFile implements iAuthorize
{
    /**
     * @var DigestFileCredential
     */
    protected $credential;

    /**
     * @var AbstractIdentity
     */
    protected $identity;

    /**
     * @var string default get_class
     */
    protected $namespace;

    /**
     * Change Authorization Namespace
     *
     * - isolate the authentication process
     *   used by storage to determine owned data
     *
     * @param string $namespace
     *
     * @return $this
     */
    function toNamespace($namespace)
    {
        $this->namespace = $namespace;

        return $this;
    }

    /**
     * Get Namespace
     *
     * @return string
     */
    function getCurrNamespace()
    {
        if (!$this->namespace)
            $this->toNamespace(get_class($this));

        return $this->namespace;
    }

    /**
     * Credential
     *
     * - it`s contains credential fields used by
     *   authorize() to authorize user.
     *   maybe, user/pass or ip address in some case
     *   that we want auth. user by ip
     *
     * - it may be vary from within different Authorize
     *   services
     *
     * @param null|array|AbstractOptions $options Builder Options
     *
     * @return $this|DigestFileCredential
     */
    function credential($options = null)
    {
        if (!$this->credential)
            $this->credential = new DigestFileCredential;

        if ($options !== null) {
            $this->credential->from($options);
            // $auth->credential(['usr' => 'payam', 'psw' => '***'])
            //    ->authorize();
            return $this;
        }

        return $this->credential;
    }

    /**
     * Authorize
     *
     * - throw exception from Authorize\Exceptions
     *   also you can throw your app meaning exception
     *   like: \App\Auth\UserBannedException
     *   to catch behaves
     *
     * - each time called will clean current storage
     * - after successful authentication it will fill
     *   the identity
     *   note: for iAuthorizeUserDataAware
     *         it used user data model to retrieve data
     *
     * @throws \Exception
     * @return $this
     */
    function authenticate()
    {
        // Clear Old Authenticated User(if has it):
        $this->identity()->logout();

        // Authorize User:

        foreach ($this->credential()->props()->readable as $option) {
            // All Options must be set
            if ($this->credential()->{$option} == ''
                ||
                $this->credential()->{$option} == null
            ) {
                throw new \InvalidArgumentException(
                    "'$option' required and must be set before authentication."
                );
            }
        }

        $hFile = @fopen($this->credential()->getFilename(), 'r');
        if ($hFile === false)
            throw new \RuntimeException(
                "Cannot open '{$this->credential()->getFilename()}' for reading"
            );

        $realm    = $this->credential()->getRealm();
        $username = $this->credential()->getUsername();
        $password = $this->credential()->getPassword();

        $id       = "$username:$realm";
        $result   = false;
        while (($line = fgets($hFile)) !== false) {
            $line = trim($line);
            if (substr($line, 0, strlen($id)) !== $id)
                continue;

            if (substr($line, -32) === md5("$username:$realm:$password")) {
                $result = true;
                break;
            }
        }

        if (!$result)
            throw new WrongCredentialException('Invalid Username or password.');

        // Set Identified User:

        $this->identity()->setUserIdentity(
            $this->credential()->getUserIdentity()
        );

        return $this;
    }

    /**
     * Authorized User Identity
     *
     * - when ew have empty identity
     *   it means we have not authorized yet
     *
     * @return iIdentity
     */
    function identity()
    {
        if (!$this->identity)
            $this->identity = new AbstractIdentity($this->getCurrNamespace());

        $this->identity->setNamespace($this->getCurrNamespace());

        return $this->identity;
    }
}
