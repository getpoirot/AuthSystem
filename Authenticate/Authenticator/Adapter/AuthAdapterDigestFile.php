<?php
namespace Poirot\AuthSystem\Authenticate\Authenticator\Adapter;

use Poirot\AuthSystem\Authenticate\Exceptions\exMissingCredential;
use Poirot\AuthSystem\Authenticate\Exceptions\exWrongCredential;
use Poirot\AuthSystem\Authenticate\Identity\IdentityHttpDigest;
use Poirot\AuthSystem\Authenticate\Identity\IdentityUsername;
use Poirot\AuthSystem\Authenticate\Interfaces\iIdentity;

use Poirot\Std\ErrorStack;

class AuthAdapterDigestFile 
    extends aAuthAdapter
{
    protected $username;
    protected $password;
    
    /** @var string Path to file contains digest passwords */
    protected $pwd_file_path;

    /**
     * Do Match Identity With Given Options/Credential
     *
     * @param array $options Include Credential Data
     *
     * @return iIdentity
     * @throws \Exception
     */
    function doIdentityMatch(array $options)
    {
        ErrorStack::handleError(E_WARNING); // {
            $hFile = fopen($this->getPwdFilePath(), 'r');
        $error = ErrorStack::handleDone();  // }

        if ($hFile === false)
            throw new \RuntimeException("Cannot open '{$this->getPwdFilePath()}' for reading", 0, $error);


        $username = $this->getUsername();
        $password = $this->getPassword();
        if (!isset($username))
            throw new exMissingCredential('Adapter Credential not contains Username.');

        $realm = $this->getRealm();

        $id       = "$username:$realm";
        while (($line = fgets($hFile)) !== false) {
            $line = trim($line);
            if (substr($line, 0, strlen($id)) !== $id)
                ## try next (user:realm) not match
                continue;

            if (!isset($password))
                ## username match, digest http auth. need secret key
                return new IdentityHttpDigest(array('username' => $username, 'hash' => strtolower(substr($line, -32))));

            if (isset($password)
                ## 32 for md5 length
                && strtolower(substr($line, -32)) === strtolower(md5("$username:$realm:$password"))
            )
                ## user/pass credential match
                return new IdentityUsername(array('username' => $username));
        }

        throw new exWrongCredential('Invalid Username or password.');
    }
    
    
    // Credentials as Options:

    /**
     * @required
     * 
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
        $this->username = (string) $username;
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
        $this->password = (string) $password;
        return $this;
    }

    // Options:

    /**
     * @return string
     */
    public function getPwdFilePath()
    {
        if (!$this->pwd_file_path)
            $this->pwd_file_path = realpath(__DIR__.'/../../../data/users.pws');

        return $this->pwd_file_path;
    }

    /**
     * @param string $filename
     * @return $this
     */
    public function setPwdFilePath($filename)
    {
        $this->pwd_file_path = $filename;
        return $this;
    }
}
