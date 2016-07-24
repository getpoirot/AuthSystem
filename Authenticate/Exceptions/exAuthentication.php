<?php
namespace Poirot\AuthSystem\Authenticate\Exceptions;

use Poirot\AuthSystem\Authenticate\Interfaces\iAuthenticator;

class exAuthentication 
    extends \RuntimeException
{
    const EXCEPTION_DEFAULT_MESSAGE = 'Authentication Failed';
    const EXCEPTION_DEFAULT_CODE    = 403;

    /** @var iAuthenticator */
    protected $authenticator;

    function __construct(
        $message = self::EXCEPTION_DEFAULT_MESSAGE,
        $code = 403,
        \Exception $previous = null,
        iAuthenticator $authenticator = null
    )
    {
        parent::__construct($message, $code, $previous);

        $this->authenticator = $authenticator;
    }

    /**
     * Get Authenticator That Rise Exception
     * @return iAuthenticator|null
     */
    function getAuthenticator()
    {
        return $this->authenticator;
    }

    /**
     * Set Authenticator
     * @param iAuthenticator $authenticator
     * @return $this
     */
    function setAuthenticator(iAuthenticator $authenticator)
    {
        $this->authenticator = $authenticator;
        return $this;
    }
}
