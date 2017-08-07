<?php
namespace Poirot\AuthSystem\Authenticate\Exceptions;

use Poirot\AuthSystem\Authenticate\Interfaces\iAuthenticator;

use Poirot\Std\Interfaces\Pact\ipMetaProvider;
use Poirot\Std\Interfaces\Struct\iDataMean;
use Poirot\Std\Struct\DataMean;

class exAuthentication
    extends \RuntimeException
    implements ipMetaProvider
{
    const EXCEPTION_DEFAULT_MESSAGE = 'Authentication Failed.';
    const EXCEPTION_DEFAULT_CODE    = 401;

    /** @var iAuthenticator */
    protected $authenticator;
    /** @var iDataMean */
    protected $meta;

    /**
     * exAuthentication constructor.
     * 
     * @param iAuthenticator|null $authenticator
     */
    final function __construct(iAuthenticator $authenticator = null)
    {
        $this->authenticator = $authenticator;
        parent::__construct(static::EXCEPTION_DEFAULT_MESSAGE, static::EXCEPTION_DEFAULT_CODE);
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

    /**
     * @return iDataMean
     */
    function meta()
    {
        if (!$this->meta)
            $this->meta = new DataMean();
        
        return $this->meta;
    }
}
