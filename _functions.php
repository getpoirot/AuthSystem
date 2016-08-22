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


        $hValue = false;

        $headers = $request->headers();
        if ($headers->has($headerName)) {
            $h = $headers->get($headerName)->current();
            $hValue = $h->renderValueLine();
        }

        return $hValue;
    }

    /**
     * Parse Authorization Header
     *
     * Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==
     *
     * - in case of basic extract given username/password
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
            list($clientScheme) = explode(' ', trim($headerValue));
            $clientScheme       = strtolower($clientScheme);
        }

        if (!in_array($clientScheme, array('basic', 'digest')))
            throw new \Exception(sprintf('Client Scheme (%s) Not Supported.', $clientScheme));

        if ($clientScheme == 'basic')
            $parsed = parseBasicAuthorizationHeader($headerValue);
        else
            $parsed = parseDigestAuthorizationHeader($headerValue);

        return $parsed;
    }

    /**
     * Parse Basic Authorization Header Value To It's
     * Credential Values
     *
     * Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==
     *
     * @param string $headerValue
     *
     * @return array [username=>'', 'password'=>'']
     * @throws \Exception Invalid Header
     */
    function parseBasicAuthorizationHeader($headerValue)
    {
        // Decode the Authorization header
        $auth = substr($headerValue, strlen('Basic '));
        $auth = base64_decode($auth);
        if (!$auth)
            throw new \RuntimeException('Unable to base64_decode Authorization header value');

        if (!ctype_print($auth))
            throw new \Exception('Invalid or Empty Authorization Credential.');

        $creds = array_filter(explode(':', $auth));
        if (count($creds) != 2)
            throw new \Exception('Invalid Authorization Credential; Missing username or password.');

        $credential = array('username' => $creds[0], 'password' => $creds[1], 0=>$creds[0], 1=>$creds[1]);
        return $credential;
    }

    /**
     * Parse Digest Authorization header
     *
     * credentials = "Digest" digest-response
     * digest-response = 1#( username | realm | nonce | digest-uri
     *      | response | [ algorithm ] | [cnonce] | [opaque]
     *      | [message-qop] | [nonce-count] | [auth-param] )
     *
     * @param string $headerValue
     *
     * @return array
     * @throws \Exception Invalid Header
     */
    function parseDigestAuthorizationHeader($headerValue)
    {
        preg_match_all('@(\w+)=(?:(?:")([^"]+)"|([^\s,$]+))@', $headerValue, $matches, PREG_SET_ORDER);
    
        $data = array();
        foreach ($matches as $m) {
            $key   = $m[1];
            $value = ($m[2]) ? $m[2] : $m[3];
    
            switch ($key) {
                case 'realm':
                case 'username': 
                    if (!ctype_print($value))
                        throw new \Exception('Invalid "realm" or "username"');
                    break;
                case 'nonce': 
                    if (!ctype_xdigit($value)) 
                        throw new \Exception('Invalid "nonce"');
                    break;
                /*
                * A string of 32 hex digits computed as defined below, which proves
                * that the user knows a password
                */
                case 'response': 
                    if (32 != strlen($value) || !ctype_xdigit($value)) 
                        throw new \Exception('Invalid "response"');
                    break;
                /*
                 * Indicates what "quality of protection" the client has applied to
                 * the message. If present, its value MUST be one of the alternatives
                 * the server indicated it supports in the WWW-Authenticate header.
                 */
                case 'qop':
                    break;
                /*
                 * This MUST be specified if a qop directive is sent (see above), and
                 * MUST NOT be specified if the server did not send a qop directive in
                 * the WWW-Authenticate header field. The nc-value is the hexadecimal
                 * count of the number of requests (including the current request)
                 * that the client has sent with the nonce value in this request. For
                 * example, in the first request sent in response to a given nonce
                 * value, the client sends "nc=00000001". The purpose of this
                 * directive is to allow the server to detect request replays by
                 * maintaining its own copy of this count - if the same nc-value is
                 * seen twice, then the request is a replay.
                 */
                case 'nc': 
                    if (8 != strlen($value) || !ctype_xdigit($value)) 
                        throw new \Exception('Invalid "nc"');
                    break;
            }
    
            $data[$key] = $value;
        }
    
        return $data;
    
        ## cnonce -----------------------------------------------------------------
        /*
         * Nonce-count. This a hexadecimal serial number for the request.
         * The client should increase this number by one for every request.
         *
         * This MUST be specified if a qop directive is sent (see above), and
         * MUST NOT be specified if the server did not send a qop directive in
         * the WWW-Authenticate header field. The cnonce-value is an opaque
         * quoted string value provided by the client and used by both client
         * and server to avoid chosen plaintext attacks, to provide mutual
         * authentication, and to provide some message integrity protection.
         */
    }
}
