<?php
namespace Poirot\AuthSystem\Authenticate\Authenticator\Adapter;

use Poirot\AuthSystem\Authenticate\Credential\CredentialUserPass;
use Poirot\AuthSystem\Authenticate\Exceptions\exMissingCredential;
use Poirot\AuthSystem\Authenticate\Exceptions\exWrongCredential;
use Poirot\AuthSystem\Authenticate\Identity\HttpDigestIdentity;
use Poirot\AuthSystem\Authenticate\Identity\IdentityUsername;
use Poirot\AuthSystem\Authenticate\Interfaces\iCredential;
use Poirot\AuthSystem\Authenticate\Interfaces\iIdentity;
use Poirot\Std\ErrorStack;

class DigestFileAuthAdapter extends AbstractAuthAdapter
{
    protected $filename;

    /**
     * Get Identity Match By Identity
     *
     * @param iCredential|null $credential
     *
     * @throws exWrongCredential
     * @throws \Exception Credential not fulfill
     * @return iIdentity
     */
    function getIdentityMatch($credential = null)
    {
        ($credential !== null) ?: $credential = $this->credential;

        if (!$credential instanceof iCredential || !$credential->isFulfilled())
            throw new \Exception(sprintf('Credential (%s) is not Fulfilled.', \Poirot\Std\flatten($credential)));

        ErrorStack::handleError(E_WARNING);
        $hFile = fopen($this->getFilename(), 'r');
        $error = ErrorStack::handleDone();
        if ($hFile === false)
            throw new \RuntimeException("Cannot open '{$this->getFilename()}' for reading", 0, $error);


        /** @var string $username */
        /** @var string $password */
        extract(\Poirot\Std\iterator_to_array($credential));
        if (!isset($username))
            throw new exMissingCredential(sprintf(
                'Credential (%s) not contains Username.', get_class($credential)
            ));

        $realm = $this->getRealm();

        $id       = "$username:$realm";
        while (($line = fgets($hFile)) !== false) {
            $line = trim($line);
            if (substr($line, 0, strlen($id)) !== $id)
                ## try next (user:realm) not match
                continue;

            if (!isset($password))
                ## username match, digest http auth. need secret key
                return new HttpDigestIdentity(['username' => $username, 'hash' => strtolower(substr($line, -32))]);

            if (isset($password)
                ## 32 for md5 length
                && strtolower(substr($line, -32)) === strtolower(md5("$username:$realm:$password"))
            )
                ## user/pass credential match
                return new IdentityUsername(['username' => $username]);
        }

        throw new exWrongCredential('Invalid Username or password.');
    }

    /**
     * @return iCredential
     */
    static function newCredential()
    {
        return new CredentialUserPass;
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
