<?php
namespace Poirot\AuthSystem\Authenticate;

use Poirot\Http\Interfaces\Message\iHttpRequest;
use Poirot\Http\Interfaces\Message\iHttpResponse;
use Poirot\Http\Message\HttpRequest;
use Poirot\Http\Message\HttpResponse;

trait TraitHttpIdentifier
{
    /** @var HttpRequest */
    protected $request;
    /** @var HttpResponse */
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
        $this->request = new HttpRequest($request);
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
