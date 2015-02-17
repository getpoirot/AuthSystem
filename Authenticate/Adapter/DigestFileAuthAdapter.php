<?php
namespace Poirot\AuthSystem\Adapter;

use Poirot\AuthSystem\AbstractAdapter;
use Poirot\AuthSystem\Authorize\Exceptions\WrongCredentialException;
use Poirot\Core\AbstractOptions;

class DigestFileAuthAdapter extends AbstractAdapter
{
    /**
     * @var DigestFileAuthCredential
     */
    protected $credential;

    /**
     * Authorize
     *
     * - throw exception from Authorize\Exceptions
     *   also you can throw your app meaning exception
     *   like: \App\Auth\UserBannedException
     *   to catch behaves
     *
     * - set authenticated user identity
     *   $this->identity()->setUserIdentity($user_identity)
     *
     * note: each time called will clean current storage
     *       can happen with $this->identity()->logout()
     *
     * note: after successful authentication, you must call
     *       login() outside of method to store identified user
     *
     * note: for iAuthorizeUserDataAware
     *       it used user data model to retrieve data
     *       on authentication in case of user isActive
     *       and so on ...
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

        $hFile = @fopen($this->credential()->getFilePathname(), 'r');
        if ($hFile === false)
            throw new \RuntimeException(
                "Cannot open '{$this->credential()->getFilePathname()}' for reading"
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
     * note: just for IDE Completion Fix
     *
     * @inheritdoc
     *
     * @param null $options
     *
     * @return $this|DigestFileAuthCredential
     */
    function credential($options = null)
    {
        return parent::credential($options);
    }

    /**
     * Get Instance of credential Object
     *
     * @return $this::credential
     */
    protected function insCredential()
    {
        return new DigestFileAuthCredential();
    }
}
