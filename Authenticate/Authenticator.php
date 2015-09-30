<?php
namespace Poirot\AuthSystem\Authenticate;

use Poirot\AuthSystem\Authenticate\AbstractAuthenticator;
use Poirot\AuthSystem\Authenticate\Abstracts\AbstractOptions;
use Poirot\AuthSystem\Authenticate\Adapter\UserPassCredential;
use Poirot\AuthSystem\Authenticate\Exceptions\AuthenticationException;
use Poirot\AuthSystem\Authenticate\Interfaces\iCredential;
use Poirot\AuthSystem\BaseIdentity;

class Authenticator extends AbstractAuthenticator
{

    /**
     * Authenticate
     *
     * - throw exception from Authenticate\Exceptions
     *   also you can throw your app meaning exception
     *   like: \App\Auth\UserBannedException
     *   to catch behaves
     *
     * - each time called will clean current storage
     * - after successful authentication, you must call
     *   login() to save identified user
     *
     *   note: for iAuthorizeUserDataAware
     *         it used user data model to retrieve data
     *         on authentication in case of user isActive
     *         and so on ...
     *
     * @throws AuthenticationException
     * @return $this
     */
    function authenticate()
    {
        if ($this->credential()->getName() == '127.0.0.1') {
            // set identity to super admin
            // ...

            return (new BaseIdentity('*'))->setUid('majid');
        }
    }

    /**
     * Get Instance of credential Object
     *
     * @param null|array|AbstractOptions $options Builder Options
     *
     * @return iCredential
     */
    protected function insCredential($options)
    {
        return $options;
    }
}