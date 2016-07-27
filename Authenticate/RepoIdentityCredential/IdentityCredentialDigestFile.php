<?php
namespace Poirot\AuthSystem\Authenticate\RepoIdentityCredential;

use Poirot\AuthSystem\Authenticate\Exceptions\exMissingCredential;
use Poirot\AuthSystem\Authenticate\Identity\IdentityHttpDigest;
use Poirot\AuthSystem\Authenticate\Identity\IdentityUsername;
use Poirot\AuthSystem\Authenticate\Interfaces\iIdentity;

use Poirot\Std\ErrorStack;

/*
$adapter = new IdentityCredentialDigestFile();
$match   = $adapter
    ->setUsername('admin')
    ->setPassword('123456')
    ->findIdentityMatch();

if (!$match)
    throw new P\AuthSystem\Authenticate\Exceptions\exWrongCredential();

echo "Hello {$match->getUsername()}.";
*/

class IdentityCredentialDigestFile
    extends aIdentityCredentialAdapter
{
    protected $username;
    protected $password;
    
    /** @var string Path to file contains digest passwords */
    protected $pwd_file_path;

    /**
     * Do Match Identity With Given Options/Credential
     *
     * @param array $credentials Include Credential Data
     *
     * @return iIdentity|false 
     */
    protected function doFindIdentityMatch(array $credentials)
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

            if (!isset($password)) {
                ## username match, digest http auth. need secret key
                $identity = new IdentityHttpDigest;
                $identity->setUsername($username);
                $identity->setHash(strtolower(substr($line, -32)));

                return $identity;
            }

            if (isset($password)
                ## 32 for md5 length
                && strtolower(substr($line, -32)) === strtolower(md5("$username:$realm:$password"))
            ) {
                ## user/pass credential match
                $identity = new IdentityUsername;
                $identity->setUsername($username);

                return $identity;
            }
        }

        return false;
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
            $this->pwd_file_path = realpath(__DIR__.'/../../data/users.pws');

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
