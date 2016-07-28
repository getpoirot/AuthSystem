<?php
namespace Poirot\AuthSystem\Authenticate\Exceptions;

use Poirot\AuthSystem\Authenticate\Interfaces\iAuthenticator;

class exAuthentication 
    extends \RuntimeException
{
    const EXCEPTION_DEFAULT_MESSAGE = 'Authentication Failed.';
    const EXCEPTION_DEFAULT_CODE    = 400;

    /** @var iAuthenticator */
    protected $authenticator;

    /**
     * exAuthentication constructor.
     * 
     * @param iAuthenticator|null $authenticator
     */
    function __construct(iAuthenticator $authenticator = null)
    {
        $this->authenticator = $authenticator;
        parent::__construct(self::EXCEPTION_DEFAULT_MESSAGE, self::EXCEPTION_DEFAULT_CODE);
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

    /**
     * Issue To Handle Authentication Exception
     *
     * usually called when authentication exception rise
     * to challenge client to login form or something.
     *
     * [code:]
     * // ..
     * } catch (P\AuthSystem\Authenticate\Exceptions\exAuthentication $e) {
     *     echo '<h1>You MUST Login:</h1>';
     *     // Challenge User For Credential Login:
     *     $e->issueException();
     * }
     * [code]
     * 
     * @return void
     */
    function issueException()
    {
        if (!$authenticator = $this->getAuthenticator())
            // Not Identifier Handle Error!! Let It Go...
            throw $this;

        $authenticator->identifier()->issueException($this);
    }
}
