# Poirot\AuthSystem

HTTP authentication using PSR-7 interfaces.

It uses PSR-7 interface implementation for request and response classes that will read the authentication request values and generates the necessary responses.

Separate classes implement the authentication of users from a file based database of user and password records.

It provides classes to check if the user is already logged in an authenticate him in case he isn't.

## Overview usage sample

```php
$request  = new HttpRequest(new PhpServerRequestBuilder);
$response = new HttpResponse(new PhpServerResponseBuilder);
$lazyLoad = new LazyFulfillmentIdentity(['fulfillment_by' => 'username', 'data_provider' => new UserData]);
$auth     = new Authenticator\HttpSessionAuth([
    'identity' => $lazyLoad,
    'request'  => $request,
    'response' => $response,
]);
try {
    $credential = null;
    ## check user has authenticated
    login_user:
    $auth->authenticate($credential);
    echo 'Continue ...';
    if (!$auth->isSignIn()) {
        $auth->signIn();
        header('Location: '.$request->getUri()->getPath()->toString());
        die();
    }
} catch (WrongCredentialException $e) {
    throw new \Exception('Invalid Username or Password.');
} catch (UserNotFoundException $e) {
    throw new \Exception('Invalid Username or Password.');
} catch (AuthenticationException $e)
{
    if ($e->getAuthenticator() instanceof Authenticator\HttpSessionAuth)
    {
        ### handle login with satisfy request
        if ($request->plg()->methodType()->isPost()) {
            $credential = new UserPassCredential($request->plg()->phpServer()->getPost());
            goto login_user;
        }
        ### challenge user with login form, redirection or etc.
        $response->setBody('
                <form method="post" action="" enctype="application/x-www-form-urlencoded">
                     <input type="text" name="email">
                     <input type="password" name="password">
                     <input type="submit" value="send">
                </form>
                <p>Please Login ...</p>
            ');
    }
}
## run rest of program
if ($auth->hasAuthenticated()) {
    $response->setBody("<h1>Hello User {$auth->identity()->getEmail()}</h1>");
}
### send response
$response->flush();
```

## TODO
- Aggregate Authenticator
- Aggregate Adapter
- Write Authentication Service Layer On Top Of Adapters For Application Dispatching Control 
