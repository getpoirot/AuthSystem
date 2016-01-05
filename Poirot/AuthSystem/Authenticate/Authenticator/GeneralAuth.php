<?php
namespace Poirot\AuthSystem\Authenticate\Authenticator;

use Poirot\AuthSystem\Authenticate\AbstractAuthenticator;
use Poirot\AuthSystem\Authenticate\Exceptions\AuthenticationException;
use Poirot\AuthSystem\Authenticate\Interfaces\iAuthenticator;
use Poirot\AuthSystem\Authenticate\Interfaces\iCredential;
use Poirot\AuthSystem\Authenticate\Interfaces\iIdentity;
use Poirot\Core\AbstractOptions;
use Poirot\Core\Interfaces\iDataSetConveyor;
use Poirot\Storage\Gateway\SessionData;

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

class GeneralAuth extends AbstractAuthenticator
    implements iAuthenticator
{
    protected $_session;
    protected $_cookie;


    /**
     * Authenticate user with Credential Data and return
     * FullFilled Identity Instance
     *
     * @param iCredential|iDataSetConveyor|array $credential \
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

    /**
     * Login Authenticated User
     *
     * - Sign user in environment and server
     *   exp. store in session
     *
     * - logout current user if has
     *
     * @throws \Exception no identity defined
     * @return $this
     */
    function signIn()
    {
        if (!($identity = $this->identity) && !$identity->isFulfilled())
            throw new \Exception('Identity not exists or not fullfilled');

        $this->__session()->set(self::STORAGE_IDENTITY_KEY , $identity);
        return $this;
    }

    /**
     * Attain Identity Object From Signed Sign
     * @return iIdentity
     */
    function attainSignedIdentity()
    {
        $identity = $this->__session()->get(self::STORAGE_IDENTITY_KEY);
        return $identity;
    }

    /**
     * Logout Authenticated User
     *
     * - it must destroy sign
     *   ie. destroy session or invalidate token in storage
     *
     * - clear identity
     *
     * @return void
     */
    function signOut()
    {
        $this->__session()->destroy();
        $this->identity()->clean();
    }

    /**
     * Has User Logged in?
     *
     * - login mean that user identity signed with signIn method
     *   exp. Exists in Session or as a header in Request Http or etc..
     *
     * - validate sign
     *   ie. with token it must be exists and validate on server
     *
     * @return boolean
     */
    function isSignIn()
    {
        if($this->__session()->has(self::STORAGE_IDENTITY_KEY))
            return true;

        return false;
    }


    // ...

    /**
     * Get Session Storage
     * @return SessionData
     */
    function __session()
    {
        if(!$this->_session)
            $this->_session = new SessionData(['realm' => $this->getRealm()]);

        return $this->_session;
    }
}
