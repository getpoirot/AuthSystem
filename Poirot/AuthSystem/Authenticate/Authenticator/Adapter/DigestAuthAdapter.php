<?php
namespace Poirot\AuthSystem\Authenticate\Authenticator\Adapter;

use Poirot\AuthSystem\Authenticate\Credential\UserPassCredential;
use Poirot\AuthSystem\Authenticate\Exceptions\MissingCredentialException;
use Poirot\AuthSystem\Authenticate\Exceptions\WrongCredentialException;
use Poirot\AuthSystem\Authenticate\Identity\UsernameIdentity;
use Poirot\AuthSystem\Authenticate\Interfaces\iCredential;
use Poirot\AuthSystem\Authenticate\Interfaces\iIdentity;
use Poirot\Core\ErrorStack;

class DigestAuthAdapter extends AbstractAuthAdapter
{
    protected $filename;

    /**
     * Get Identity Match By Identity
     *
     * @param iCredential $credential
     *
     * @throws WrongCredentialException
     * @throws \Exception Credential not fulfill
     * @return iIdentity
     */
    function doIdentityMatch($credential)
    {
        if (!$credential->isFulfilled())
            throw new \Exception(sprintf('Credential (%s) is not Fulfilled.', get_class($credential)));

        ErrorStack::handleError(E_WARNING);
        $hFile = fopen($this->getFilename(), 'r');
        $error = ErrorStack::handleDone();
        if ($hFile === false)
            throw new \RuntimeException("Cannot open '{$this->getFilename()}' for reading", 0, $error);


        /** @var string $username */
        /** @var string $password */
        extract($credential->toArray());
        if (!isset($username) || !isset($password))
            throw new MissingCredentialException(sprintf(
                'Credential (%s) not contains Username or Password.', get_class($credential)
            ));

        $realm = $this->getRealm();

        $id       = "$username:$realm";
        $result   = false;
        while (($line = fgets($hFile)) !== false) {
            $line = trim($line);
            if (substr($line, 0, strlen($id)) !== $id)
                ## try next (user:admin) not match
                continue;

            if (strtolower(substr($line, -32)) === strtolower(md5("$username:$realm:$password"))) {
                $result = true;
                break;
            }
        }
        if (!$result)
            throw new WrongCredentialException('Invalid Username or password.');

        // Set Identified User:
        return new UsernameIdentity(['username' => $username]);
    }

    /**
     * @return iCredential
     */
    static function newCredential()
    {
        return new UserPassCredential;
    }


    // Options:

    /**
     * @return string
     */
    public function getFilename()
    {
        if (!$this->filename)
            $this->filename = realpath(__DIR__.'/../../../data/users.pws');

        return $this->filename;
    }

    /**
     * @param string $filename
     * @return $this
     */
    public function setFilename($filename)
    {
        $this->filename = $filename;
        return $this;
    }
}
