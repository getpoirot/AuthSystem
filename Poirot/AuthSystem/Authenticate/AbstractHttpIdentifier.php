<?php
namespace Poirot\AuthSystem\Authenticate;

use Poirot\AuthSystem\Authenticate\Interfaces\HttpMessageAware\iIdentifier;
use Poirot\Http\Interfaces\Message\iHttpRequest;
use Poirot\Http\Interfaces\Message\iHttpResponse;
use Poirot\Http\Message\HttpResponse;

abstract class AbstractHttpIdentifier extends AbstractIdentifier
    implements iIdentifier
{
    /** @var iHttpRequest */
    protected $request;
    /** @var iHttpResponse */
    protected $response;

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

    /**
     * Set Response
     *
     * @param iHttpResponse $response
     *
     * @return $this
     */
    function setResponse(iHttpResponse $response)
    {
        $this->response = $response;
        return $this;
    }

    /**
     * Http Response
     *
     * @return iHttpResponse
     */
    function response()
    {
        if (!$this->response)
            $this->response = new HttpResponse;

        return $this->response;
    }
}
