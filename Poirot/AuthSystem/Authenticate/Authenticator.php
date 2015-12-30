<?php
namespace Poirot\AuthSystem\Authenticate;

use Poirot\AuthSystem\Authenticate\Adapter\UserPassCredential;
use Poirot\AuthSystem\Authenticate\Exceptions\AuthenticationException;
use Poirot\AuthSystem\Authenticate\Interfaces\iCredential;
use Poirot\AuthSystem\Authenticate\Interfaces\iIdentity;
use Poirot\Core\AbstractOptions;

// TODO authenticator adapter

class Authenticator extends AbstractAuthenticator
{
    /**
     * Authenticate user with Credential Data and return
     * FullFilled Identity Instance
     *
     * @throws AuthenticationException Or extend of this
     * @return iIdentity|void
     */
    protected function doAuthenticate()
    {
        if(($email = $this->credential()->getEmail()) == 'john@Doe.com'
            && ($password = $this->credential()->getPassword()) == '123456') {
            $uuid = md5($email.':'.$password);

            return new BaseIdentity($uuid, $this->credential()->toArray());
        }
    }


    /**
     * @inheritdoc
     * @return UserPassCredential|$this
     */
    function credential($options = null)
    {
        return parent::credential($options);
    }

    /**
     * Get Instance of credential Object
     *
     * @param null|array|AbstractOptions $options Builder Options
     *
     * @return iCredential
     */
    function newCredential($options = null)
    {
        $credential = new UserPassCredential;

        if ($options !== null)
            $credential->from($options);

        return $credential;
    }
}
