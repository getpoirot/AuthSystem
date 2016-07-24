<?php
namespace Poirot\AuthSystem\Authenticate;

use Poirot\AuthSystem\Authenticate\Interfaces\HttpMessageAware\iAuthenticator;

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
    
}
