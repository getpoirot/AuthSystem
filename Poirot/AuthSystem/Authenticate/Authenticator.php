<?php
namespace Poirot\AuthSystem\Authenticate;

use Poirot\AuthSystem\Authenticate\Adapter\UserPassCredential;
use Poirot\AuthSystem\Authenticate\Exceptions\AuthenticationException;
use Poirot\AuthSystem\Authenticate\Interfaces\iCredential;
use Poirot\AuthSystem\Authenticate\Interfaces\iIdentifier;
use Poirot\Core\AbstractOptions;

// TODO authenticator adapter

class Authenticator extends AbstractAuthenticator
{
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
     * @throws AuthenticationException Or extend of this
     * @return iIdentifier
     */
    function authenticate()
    {
        if(($email = $this->credential()->getEmail()) == 'john@Doe.com'
            && ($password = $this->credential()->getPassword()) == '123456') {
            $uuid = md5($email.':'.$password);
            return new BaseIdentifier(['identity' =>
                new BaseIdentity(
                    $uuid                   ## user uid
                    , $this->credential()   ## user data as options
                )
            ]);
        }

        throw new AuthenticationException('user authentication failure');
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
