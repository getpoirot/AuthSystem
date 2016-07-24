<?php
namespace Poirot\AuthSystem\Authenticate;

use Poirot\AuthSystem\Authenticate\Exceptions\exAuthentication;
use Poirot\AuthSystem\Authenticate\Exceptions\exMissingCredential;
use Poirot\AuthSystem\Authenticate\Interfaces\HttpMessageAware\iAuthenticator;
use Poirot\AuthSystem\Authenticate\Interfaces\iAuthAdapter;
use Poirot\AuthSystem\Authenticate\Interfaces\iCredential;
use Poirot\AuthSystem\Authenticate\Interfaces\iCredentialHttpAware;
use Poirot\AuthSystem\Authenticate\Interfaces\iIdentity;
use Poirot\Http\HttpRequest;
use Poirot\Http\Interfaces\iHttpRequest;

/*
$auth     = new Authenticator\HttpSessionAuth([
    'identity' => $lazyLoad,
    'request'  => $request,
    'response' => $response,
]);

try {
    $auth->authenticate();
    if ($auth->isSignInRequestReceived())
        $auth->signIn();

    $response->setBody("<h1>Hello User {$auth->identity()->getEmail()}</h1>");
} catch (WrongCredentialException $e) {
    throw new \Exception('Invalid Username or Password.');
} catch (UserNotFoundException $e) {
    throw new \Exception('Invalid Username or Password.');
} catch (AuthenticationException $e)
{
    $response->setBody('
            <form method="post" action="" enctype="application/x-www-form-urlencoded">
                 <input type="text" name="email">
                 <input type="password" name="password">

                 <input type="submit" value="send">
            </form>
        ');
}

$response->flush();
*/

abstract class aAuthenticatorHttp 
    extends aAuthenticator
    implements iAuthenticator
{
    use TraitHttpIdentifier;

    /**
     * TODO merge with authenticate
     *
     * Authenticate user with Credential Data and return
     * FullFilled Identity Instance
     *
     * @param iCredential|iHttpRequest $credential \
     * Credential can be extracted from this
     *
     * @throws exAuthentication Or extend of this
     * @return iIdentity|void
     */
    protected function doAuthenticate($credential = null)
    {
        if ($credential === null)
            $credential = $this->request;

        // do credential extraction on extended
        if ($credential instanceof iHttpRequest) {
            $credential = $this->doExtractCredentialFromRequest(new HttpRequest($credential));
            if (!$credential)
                // if auth credential not available it cause user get authorize require response
                $this->riseException(new exAuthentication);

            if ($credential instanceof iAuthAdapter)
                return $credential->getIdentityMatch();

            if ($credential instanceof iIdentity)
                return $credential;
        }

        if (!$credential instanceof iCredential || !$credential->isFulfilled())
            throw new exMissingCredential(sprintf('%s Credential can`t be empty.', get_class($this)));

        $identity = $this->getAdapter()->getIdentityMatch($credential);
        return $identity;
    }

    /**
     * TODO replace against doAuthenticate
     *
     * Do Extract Credential From Request Object
     * ie. post form data or token
     *
     * @param HttpRequest $request
     *
     * @return iCredential|iAuthAdapter|null Null if not available
     */
    function doExtractCredentialFromRequest(HttpRequest $request)
    {
        $credential = $this->getAdapter()->newCredential();

        if ($credential instanceof iCredentialHttpAware)
            $credential->fromRequest($request);

        if ($credential->isFulfilled())
            return $credential;
    }

    /**
     * Manipulate Response From Exception Then Throw It
     *
     * @param exAuthentication $exception
     *
     * @throws exAuthentication
     */
    protected function riseException(exAuthentication $exception)
    {
        $this->response()->setStatusCode($exception->getCode());
        $exception->setAuthenticator($this);

        throw $exception;
    }
}
