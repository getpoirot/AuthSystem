<?php
namespace Poirot\AuthSystem\Authenticate;

use Poirot\AuthSystem\Authenticate\Adapter\DigestAuthAdapter;
use Poirot\AuthSystem\Authenticate\Exceptions\AuthenticationException;
use Poirot\AuthSystem\Authenticate\Interfaces\iAuthAdapter;
use Poirot\AuthSystem\Authenticate\Interfaces\iCredential;
use Poirot\AuthSystem\Authenticate\Interfaces\iIdentity;
use Poirot\AuthSystem\Credential\OpenCredential;
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

class Authenticator extends AbstractAuthenticator
{
    /** @var iAuthAdapter */
    protected $adapter;

    /**
     * Authenticate user with Credential Data and return
     * FullFilled Identity Instance
     *
     * @throws AuthenticationException Or extend of this
     * @return iIdentity|void
     */
    protected function doAuthenticate()
    {
        $identity = $this->getAdapter()->doIdentityMatch($this->credential());

        return $identity;
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

        $this->adapter->setRealm($this->identifier()->getRealm());
        return $this->adapter;
    }


    // ...

    /**
     * @inheritdoc
     * @return OpenCredential|$this
     */
    function credential($options = null)
    {
        $credential = $this->getAdapter()->credential($options);
        return ($credential instanceof iAuthAdapter) ? $this : $credential;
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
        $credential = new OpenCredential;

        if ($options !== null)
            $credential->from($options);

        return $credential;
    }
}
