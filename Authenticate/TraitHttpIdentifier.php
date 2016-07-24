<?php
namespace Poirot\AuthSystem\Authenticate;

use Poirot\Http\HttpRequest;
use Poirot\Http\HttpResponse;
use Poirot\Http\Interfaces\iHttpRequest;
use Poirot\Http\Interfaces\iHttpResponse;

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
