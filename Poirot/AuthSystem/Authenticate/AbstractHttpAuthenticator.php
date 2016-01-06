<?php
namespace Poirot\AuthSystem\Authenticate;

use Poirot\AuthSystem\Authenticate\Exceptions\AuthenticationException;
use Poirot\AuthSystem\Authenticate\Exceptions\MissingCredentialException;
use Poirot\AuthSystem\Authenticate\Interfaces\HttpMessageAware\iAuthenticator;
use Poirot\AuthSystem\Authenticate\Interfaces\iCredential;
use Poirot\AuthSystem\Authenticate\Interfaces\iCredentialHttpAware;
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
        if ($credential instanceof iHttpRequest) {
            $credential = $this->doExtractCredentialFromRequest(new HttpRequest($credential));
            if (!$credential)
                // if auth credential not available it cause user get authorize require response
                $this->riseException(new AuthenticationException);
        }

        if (!$credential instanceof iCredential || !$credential->isFulfilled())
            throw new MissingCredentialException(sprintf('%s Credential can`t be empty.', get_class($this)));

        $identity = $this->getAdapter()->doIdentityMatch($credential);
        return $identity;
    }

    /**
     * Do Extract Credential From Request Object
     * ie. post form data or token
     *
     * @param HttpRequest $request
     *
     * @return iCredential|null Null if not available
     */
    function doExtractCredentialFromRequest(HttpRequest $request)
    {
        $credential = $this->getAdapter()->newCredential();
        if ($credential instanceof iCredentialHttpAware)
            $credential->fromRequest($request);

        if ($credential->isFulfilled())
            return $credential;
    }

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
