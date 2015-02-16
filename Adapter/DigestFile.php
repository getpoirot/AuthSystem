<?php
namespace Poirot\Authentication\Adapter;

use Poirot\Authentication\AbstractAdapter;
use Poirot\Authentication\Authorize\Exceptions\WrongCredentialException;
use Poirot\Authentication\Interfaces\iCredential;
use Poirot\Core\AbstractOptions;

class DigestFile extends AbstractAdapter
{
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

        /** @var string $realm */
        /** @var string $username */
        /** @var string $password */
        /** @var string $user_identity */
        extract($this->credential()->toArray());

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

        $this->identity()->setUserIdentity($user_identity);

        return $this;
    }

    /**
     * Get Instance of credential Object
     *
     * @return iCredential
     */
    protected function insCredential()
    {
        return new DigestFileCredential();
    }
}
