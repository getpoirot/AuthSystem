<?php
namespace Poirot\AuthSystem\Authenticate\Authenticator;

use Poirot\AuthSystem\Authenticate\AbstractAuthenticator;
use Poirot\AuthSystem\Authenticate\Interfaces\HttpMessageAware\iAuthenticator;
use Poirot\AuthSystem\Authenticate\Interfaces\HttpMessageAware\iIdentifier as HttpMessageIdentifier;
use Poirot\AuthSystem\Authenticate\Interfaces\iIdentifier;
use Poirot\Http\Interfaces\Message\iHttpRequest;

class HttpMessageAuth extends AbstractAuthenticator
    implements iAuthenticator
{
    /** @var iHttpRequest */
    protected $request;

    /**
     * Get Default Identifier Instance
     *
     * @return iIdentifier|HttpMessageIdentifier
     */
    function getDefaultIdentifier()
    {
        // TODO: Implement getDefaultIdentifier() method.
    }

    /**
     * Set Request
     *
     * @param iHttpRequest $request
     *
     * @return $this
     */
    function setRequest(iHttpRequest $request)
    {
        $this->request = $request;
        return $this;
    }
}
