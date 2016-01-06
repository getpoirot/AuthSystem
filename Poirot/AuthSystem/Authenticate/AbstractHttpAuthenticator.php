<?php
namespace Poirot\AuthSystem\Authenticate;

use Poirot\AuthSystem\Authenticate\Exceptions\AuthenticationException;
use Poirot\AuthSystem\Authenticate\Interfaces\HttpMessageAware\iAuthenticator;
use Poirot\AuthSystem\Authenticate\Interfaces\iCredential;
use Poirot\AuthSystem\Authenticate\Interfaces\iIdentity;
use Poirot\Core\AbstractOptions;
use Poirot\Http\Interfaces\Message\iHttpRequest;
use Poirot\Http\Message\HttpRequest;

abstract class AbstractHttpAuthenticator extends AbstractAuthenticator
    implements iAuthenticator
{
    use TraitHttpIdentifier;

    /**
     * Authenticate user with Credential Data and return
     * FullFilled Identity Instance
     *
     * @param iCredential|iHttpRequest $credential \
     * Credential can be extracted from this
     *
     * @throws AuthenticationException Or extend of this
     * @return iIdentity|void
     */
    protected function doAuthenticate($credential = null)
    {
        if ($credential === null)
            $credential = $this->request;

        // do credential extraction on extended
        if ($credential instanceof iHttpRequest)
            $credential = $this->doExtractCredentialFromRequest(new HttpRequest($credential));

        if (!$credential instanceof iCredential)
            throw new \InvalidArgumentException(sprintf('%s Credential can`t be empty.', get_class($this)));

        $identity = $this->getAdapter()->doIdentityMatch($credential);
        return $identity;
    }

    /**
     * Do Extract Credential From Request Object
     * ie. post form data or token
     *
     * @param HttpRequest $request
     *
     * @throws AuthenticationException if auth credential not available
     *         it cause user get authorize require response
     *
     * @return iCredential
     */
    abstract function doExtractCredentialFromRequest(HttpRequest $request);

    /**
     * Manipulate Response From Exception Then Throw It
     *
     * @param AuthenticationException $exception
     *
     * @throws AuthenticationException
     */
    protected function riseException(AuthenticationException $exception)
    {
        $this->response()->setStatCode($exception->getCode());

        throw $exception;
    }
}
