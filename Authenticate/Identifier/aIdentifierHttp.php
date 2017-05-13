<?php
namespace Poirot\AuthSystem\Authenticate\Identifier;

use Poirot\Http\HttpMessage\Request\DataParseRequestPhp;
use Poirot\Http\HttpMessage\Response\BuildHttpResponse;
use Poirot\Http\HttpMessage\Response\DataParseResponsePhp;
use Poirot\Http\HttpRequest;
use Poirot\Http\HttpResponse;
use Poirot\Http\Interfaces\iHttpRequest;
use Poirot\Http\Interfaces\iHttpResponse;
use Poirot\Http\Interfaces\Respec\iRequestAware;
use Poirot\Http\Interfaces\Respec\iRequestProvider;
use Poirot\Http\Interfaces\Respec\iResponseAware;
use Poirot\Http\Interfaces\Respec\iResponseProvider;


/**
 * Identifier is an object that recognize user in each request
 * or tell that has no recognized user exists.
 * then we can achieve user data with identity that fulfilled with required
 * data.
 *
 * Sign In/Out User as Identity into Environment(by session or something)
 *
 * - if identity is fulfilled/validated means user is recognized
 * - you can sign-in fulfillment identity
 * - sign-in/out take control of current identifier realm
 * - sign in some cases can be happen on request/response headers
 *
 */
abstract class aIdentifierHttp
    extends aIdentifier
    implements iRequestAware
    , iResponseAware
    , iRequestProvider
    , iResponseProvider
{
    /** @var iHttpRequest */
    protected $request;
    /** @var iHttpResponse */
    protected $response;


    // Implement Request/Response Aware

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
     * Http Request
     *
     * !! most time the request object must inject into class
     *    and manipulated during authentication flow.
     *
     * @return iHttpRequest
     */
    function request()
    {
        if (!$this->request) {
            $request = new HttpRequest(new DataParseRequestPhp);
            $this->request = $request;
        }

        return $this->request;
    }

    /**
     * Http Response
     *
     * !! most time the response object must inject into class
     *    and manipulated during authentication flow.
     *
     * @return iHttpResponse
     */
    function response()
    {
        if (!$this->response) {
            $settings = new DataParseResponsePhp;
            $response = new HttpResponse(
                new BuildHttpResponse( BuildHttpResponse::parseWith($settings) )
            );

            $this->response = $response;
        }

        return $this->response;
    }
}
