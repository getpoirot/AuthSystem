<?php
namespace Poirot\AuthSystem\Authenticate\Authenticator;

use Poirot\AuthSystem\Authenticate\AbstractAuthenticator;
use Poirot\AuthSystem\Authenticate\Exceptions\AuthenticationException;
use Poirot\AuthSystem\Authenticate\Interfaces\iAuthenticator;
use Poirot\AuthSystem\Authenticate\Interfaces\iCredential;
use Poirot\AuthSystem\Authenticate\Interfaces\iIdentity;
use Poirot\Std\Interfaces\Struct\iDataStruct;

class PhpSessionAuth extends AbstractAuthenticator
    implements iAuthenticator
{
    use TraitSessionAuth;

    /**
     * Authenticate user with Credential Data and return
     * FullFilled Identity Instance
     *
     * @param iCredential|iDataStruct|array $credential \
     * Credential can be extracted from this
     *
     * @throws AuthenticationException Or extend of this
     * @return iIdentity|void
     */
    protected function doAuthenticate($credential = null)
    {
        if (!$credential instanceof iCredential && $credential !== null)
            $credential = $this->getAdapter()->newCredential()->from($credential);

        return parent::doAuthenticate($credential);
    }
}
