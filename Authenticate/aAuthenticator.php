<?php
namespace Poirot\AuthSystem\Authenticate;

use Poirot\AuthSystem\Authenticate\Authenticator\Adapter\AuthAdapterDigestFile;
use Poirot\AuthSystem\Authenticate\Exceptions\exAuthentication;
use Poirot\AuthSystem\Authenticate\Interfaces\iCredential;
use Poirot\AuthSystem\Authenticate\Interfaces\iIdentityCredentialRepo;
use Poirot\AuthSystem\Authenticate\Interfaces\iAuthenticator;
use Poirot\AuthSystem\Authenticate\Interfaces\iIdentity;

/*
$auth       = new Authenticator(['identity' => new UsernameIdentity]);

$request = new HttpRequest(new PhpServerRequestBuilder());
if ($request->plg()->methodType()->isPost()) {
    try {
        $POST       = $request->plg()->phpServer()->getPost();
        $credential = [
            'username' => $POST->get('email'),
            'password' => $POST->get('password'),
        ];

        ## if authenticate successfully user data available
        ## and authenticated through Identifier
        $identity = $auth->authenticate($credential);
        $identity->signIn();
        header('Location: /');
        die();
    } catch (WrongCredentialException $e) {
        throw new \Exception('Invalid Username or Password.');
    } catch (UserNotFoundException $e) {
        throw new \Exception('Invalid Username or Password.');
    } catch (AuthenticationException $e)
    {
        throw $e;
    }
}

if (!$auth->hasAuthenticated())
{
    echo <<<HTML
        <form method="post" action="" enctype="application/x-www-form-urlencoded">
             <input type="text" name="email">
             <input type="password" name="password">

             <input type="submit" value="send">
        </form>
HTML;

    die('> Please Login');
}


echo "<h1>Hello User {$auth->identifier()->identity()->getUsername()}</h1>";

die('>_');
*/

abstract class aAuthenticator
    extends aIdentifier
    implements iAuthenticator
{
    /** @var iIdentityCredentialRepo Credential Authenticate Match Adapter (check usr/pas) */
    protected $adapter;

    protected $_c__credential;

    /**
     * Authenticate
     *
     * - authenticate user using credential
     * - login into identifier with iIdentity set from recognized
     *   user data
     *
     * - it can be used to force user for login on each page that
     *   need access control
     *   ie. $auth->authenticate()
     *   if it has authenticated and not new credential passed as
     *   argument it will return and do nothing
     *
     * note: after successful authentication, you must call
     *       login() outside of method to store identified user
     *
     * @param mixed $credential \
     * Credential can be extracted from this
     *
     * @throws exAuthentication|\Exception Or extend of this
     * @return iAuthenticator|aAuthenticator
     */
    function authenticate($credential = null)
    {
        if ($this->hasAuthenticated() && ($this->_c__credential === null || $credential === $this->_c__credential))
            ## authenticated and nothing changes
            return $this;

        if ($credential instanceof iIdentityCredentialRepo) {
            $identity = $credential->findIdentityMatch();
        } else {
            if (!$credential instanceof iCredential)
                throw new \InvalidArgumentException(sprintf('%s Credential can`t be empty.', get_class($this)));

            $identity = $this->getAdapter()->findIdentityMatch($credential);
        }

        
        if (!$identity instanceof iIdentity && !$identity->isFulfilled()) {
            $e = new exAuthentication;
            $e->setAuthenticator($this);
            throw $e;
        }

        $this->identity()->import($identity);
        if (!$this->identity()->isFulfilled())
            throw new \Exception(
                'User Authenticated Successfully But Identifier Identity Not'
                .' FullFilled Satisfy with That Result.'
            );

        $this->_c__credential = $credential;
        return $this;
    }

    /**
     * Has Authenticated And Identifier Exists
     *
     * - it mean that Identifier has full filled identity
     *
     * note: this allow to register this authenticator as a service
     *       to retrieve authenticate information
     *
     * @return boolean
     */
    function hasAuthenticated()
    {
        return $this->identity()->isFulfilled();
    }


    // Options:

    /**
     * Set Authentication Adapter
     *
     * @param iIdentityCredentialRepo $adapter
     *
     * @return $this
     */
    function setAdapter(iIdentityCredentialRepo $adapter)
    {
        $this->adapter = $adapter;
        return $this;
    }

    /**
     * Get Authentication Adapter
     *
     * @return iIdentityCredentialRepo
     */
    function getAdapter()
    {
        if (!$this->adapter)
            $this->adapter = new AuthAdapterDigestFile;

        $this->adapter->setRealm($this->getRealm());
        return $this->adapter;
    }
}
