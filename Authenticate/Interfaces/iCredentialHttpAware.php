<?php
namespace Poirot\AuthSystem\Authenticate\Interfaces;

use Poirot\Http\Interfaces\iHttpRequest;

interface iCredentialHttpAware 
    extends iCredential
{
    /**
     * Set Options From Request Http Object
     *
     *  ie. extract user/pass from post data
     *
     * @param iHttpRequest $request
     *
     * @throws \Exception
     * @return $this
     */
    function fromRequest(iHttpRequest $request);
}
