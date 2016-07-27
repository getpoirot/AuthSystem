<?php
namespace Poirot\AuthSystem\Authenticate\Identifier\HttpDigest
{
    use Poirot\Http\Interfaces\iHttpRequest;

    /**
     * Has Request Contains Authorization Header
     *
     * @param iHttpRequest $request
     * @param bool         $isProxy
     * 
     * @return bool
     */
    function hasAuthorizationHeader(iHttpRequest $request, $isProxy = false)
    {
        if ($isProxy)
            $headerName = 'Proxy-Authorization';
        else
            $headerName = 'Authorization';

        $headers = $request->headers();

        $hValue = false;
        foreach ($headers->get($headerName) as $h) {
            $hValue = $h->renderValueLine();
            break;
        }
        
        return $hValue;
    }

    /**
     * Parse Authorization Header
     *
     * @param string      $headerValue
     * @param null|string $clientScheme Basic|Digest, null detect from header
     *
     * @return array
     * @throws \Exception
     */
    function parseAuthorizationHeader($headerValue, $clientScheme = null)
    {
        if ($clientScheme === null) {
            // 
            list($clientScheme) = explode(' ', trim($headerValue));
            $clientScheme       = strtolower($clientScheme);
        }

        if (!in_array($clientScheme, array('basic', 'digest')))
            ## not support, Authorization: basic .....
            throw new \Exception(sprintf('Client Scheme (%s) Not Supported.', $clientScheme));

        ## scheme not acceptable by config
        if ($clientScheme == 'digest' && !$this->isAcceptDigest())
            return null;
        if ($clientScheme == 'basic'  && !$this->isAcceptBasic())
            return null;


        if ($clientScheme == 'basic')
            $credential = $this->__computeBasicCredential($headerValue);
        else
            $credential = $this->__computeDigestCredential($headerValue);

        return $credential;
    }
}
