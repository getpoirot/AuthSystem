<?php
namespace Poirot\AuthSystem\Authenticate;

use Poirot\AuthSystem\Authenticate\Adapter\UserPassCredential;
use Poirot\AuthSystem\Authenticate\Exceptions\AuthenticationException;
use Poirot\AuthSystem\Authenticate\Interfaces\iCredential;
use Poirot\AuthSystem\Authenticate\Interfaces\iIdentity;
use Poirot\AuthSystem\Authenticate\BaseIdentity;

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
     * @return iIdentity
     */
    function authenticate()
    {
        if($this->credential()->getEmail() == 'johnDoe@yahoo.com' &&
            $this->credential()->getPassword() == '123456')
            //return new BaseIdentity($this->credential()->getUsername());
            return new BaseIdentifier();
        throw new AuthenticationException('user authentication failure');
    }

    /**
     * Get Instance of credential Object
     *
     * @param null|array|AbstractOptions $options Builder Options
     *
     *
     * @throws \Exception
     * @return iCredential
     */
    function insCredential($options)
    {
        if($this->credential)
            throw new \Exception('credential Object is already ready to use');

        $this->credential = (new UserPassCredential())->fromArray($options);

        return $this;
    }

}