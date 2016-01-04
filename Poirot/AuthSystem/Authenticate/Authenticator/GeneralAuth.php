<?php
namespace Poirot\AuthSystem\Authenticate\Authenticator;

use Poirot\AuthSystem\Authenticate\AbstractAuthenticator;
use Poirot\AuthSystem\Authenticate\Authenticator\Adapter\DigestAuthAdapter;
use Poirot\AuthSystem\Authenticate\Exceptions\AuthenticationException;
use Poirot\AuthSystem\Authenticate\Identifier\GeneralSessionIdentifier;
use Poirot\AuthSystem\Authenticate\Interfaces\iAuthAdapter;
use Poirot\AuthSystem\Authenticate\Interfaces\iAuthenticator;
use Poirot\AuthSystem\Authenticate\Interfaces\iCredential;
use Poirot\AuthSystem\Authenticate\Interfaces\iIdentifier;
use Poirot\AuthSystem\Authenticate\Interfaces\iIdentity;
use Poirot\AuthSystem\Credential\OpenCredential;
use Poirot\Core\AbstractOptions;
use Poirot\Core\Interfaces\iDataSetConveyor;

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
    /** @var iCredential */
    protected $credential;

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
     * Get Default Identifier Instance
     *
     * @return iIdentifier|GeneralSessionIdentifier
     */
    function getDefaultIdentifier()
    {
        if (!$this->default_identifier)
            $this->setDefaultIdentifier(new GeneralSessionIdentifier);

        return $this->default_identifier;
    }
}
