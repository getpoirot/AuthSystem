<?php
namespace Poirot\AuthSystem\Authenticate\Authenticator;

use Poirot\AuthSystem\Authenticate\AbstractAuthenticator;
use Poirot\AuthSystem\Authenticate\Exceptions\AuthenticationException;
use Poirot\AuthSystem\Authenticate\Interfaces\HttpMessageAware\iAuthenticator;
use Poirot\AuthSystem\Authenticate\Interfaces\HttpMessageAware\iIdentifier as HttpMessageIdentifier;
use Poirot\AuthSystem\Authenticate\Interfaces\iCredential;
use Poirot\AuthSystem\Authenticate\Interfaces\iIdentifier;
use Poirot\AuthSystem\Authenticate\Interfaces\iIdentity;
use Poirot\Http\Interfaces\Message\iHttpRequest;

class HttpMessageAuth extends AbstractAuthenticator
    implements iAuthenticator
{
    /** @var iHttpRequest */
    protected $request;

    /**
     * Authenticate
     *
     * - authenticate user using credential
     * - login into identifier with iIdentity set from recognized
     *   user data
     *
     * note: after successful authentication, you must call
     *       login() outside of method to store identified user
     *
     * @param mixed $credential \
     * Credential can be extracted from this
     *
     * @throws AuthenticationException|\Exception Or extend of this
     * @return iIdentifier|HttpMessageIdentifier
     */
    function authenticate($credential = null)
    {
        $identity = $this->doAuthenticate($credential);
        if (!$identity instanceof iIdentity && !$identity->isFulfilled())
            throw new AuthenticationException('user authentication failure.');

        $this->identifier()->identity()->from($identity);
        if (!$this->identifier()->identity()->isFulfilled())
            throw new \Exception(
                'User Authenticated Successfully But Identifier Identity Not'
                .' FullFilled Satisfy with That Result.'
            );

        return $this->identifier();
    }

    /**
     * Authenticate user with Credential Data and return
     * FullFilled Identity Instance
     *
     * @param iCredential|mixed $credential \
     * Credential can be extracted from this
     *
     * @throws AuthenticationException Or extend of this
     * @return iIdentity|void
     */
    protected function doAuthenticate($credential = null)
    {
        // do credential extraction on extended
        // ...

        $identity = $this->getAdapter()->doIdentityMatch($credential);
        return $identity;
    }

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
