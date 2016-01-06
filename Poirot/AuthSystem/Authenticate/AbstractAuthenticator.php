<?php
namespace Poirot\AuthSystem\Authenticate;

use Poirot\AuthSystem\Authenticate\Authenticator\Adapter\DigestAuthAdapter;
use Poirot\AuthSystem\Authenticate\Exceptions\AuthenticationException;
use Poirot\AuthSystem\Authenticate\Interfaces\iCredential;
use Poirot\AuthSystem\Authenticate\Interfaces\iIdentifier;
use Poirot\AuthSystem\Authenticate\Interfaces\HttpMessageAware\iIdentifier as HttpMessageIdentifier;
use Poirot\AuthSystem\Authenticate\Interfaces\iAuthAdapter;
use Poirot\AuthSystem\Authenticate\Interfaces\iAuthenticator;
use Poirot\AuthSystem\Authenticate\Interfaces\iIdentity;
use Poirot\Core\AbstractOptions;

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

abstract class AbstractAuthenticator extends AbstractIdentifier
    implements iAuthenticator
{
    /** @var iAuthAdapter Credential Authenticate Match Adapter (check usr/pas) */
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
     * @throws AuthenticationException|\Exception Or extend of this
     * @return iIdentifier|HttpMessageIdentifier
     */
    function authenticate($credential = null)
    {
        if ($this->hasAuthenticated() && ($this->_c__credential === null || $credential === $this->_c__credential))
            ## authenticated and nothing changes
            return $this;


        $identity = $this->doAuthenticate($credential);
        if (!$identity instanceof iIdentity && !$identity->isFulfilled())
            throw new AuthenticationException('user authentication failure.');

        $this->identity()->from($identity);
        if (!$this->identity()->isFulfilled())
            throw new \Exception(
                'User Authenticated Successfully But Identifier Identity Not'
                .' FullFilled Satisfy with That Result.'
            );

        $this->_c__credential = $credential;
        return $this;
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

        if (!$credential instanceof iCredential)
            throw new \InvalidArgumentException(sprintf('%s Credential can`t be empty.', get_class($this)));

        $identity = $this->getAdapter()->doIdentityMatch($credential);
        return $identity;
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
     * @param iAuthAdapter $adapter
     *
     * @return $this
     */
    function setAdapter(iAuthAdapter $adapter)
    {
        $this->adapter = $adapter;
        return $this;
    }

    /**
     * Get Authentication Adapter
     *
     * @return iAuthAdapter
     */
    function getAdapter()
    {
        if (!$this->adapter)
            $this->adapter = new DigestAuthAdapter;

        $this->adapter->setRealm($this->getRealm());
        return $this->adapter;
    }
}
