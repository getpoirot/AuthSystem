## Overview usage sample

```php
class UserData implements P\AuthSystem\Authenticate\Interfaces\iProviderIdentityData
{
    # Finds a user by the given user Identity.
    #
    # @param string $property ie. 'user_name'
    # @param mixed $value ie. 'payam@mail.com'
    #
    # @throws \Exception
    # @return EntityInterface
    #
    function findBy($property, $value)
    {
        $entity = new P\Std\Struct\DataEntity();
        if ($property == 'username' && $value == 'admin')
            ## find by user name
            $entity->import([
                'email' => 'naderi.payam@gmail.com',
                'phone' => '+989354323345',
                'facbook' => '@dfsdf',
                'avatar' => ':D',
            ]);

        return $entity;
    }
}

$authenticator = new P\AuthSystem\Authenticate\Authenticator(
    new P\AuthSystem\Authenticate\Identifier\IdentifierSession('realm_members', [
        'issuer_exception' => function($e) {
            /*echo '<h1>ACCESS Denied. <a href="/login">Login Here</a>';
            die;*/

            // ISSUER TO LOGIN USER AUTOMATICALLY!
            /** @var $e P\AuthSystem\Authenticate\Exceptions\exAuthentication */
            if (!$authenticator = $e->getAuthenticator())
                throw new \Exception('Authenticator not present.');

            $identifier = $authenticator->authenticate(['username' => 'admin', 'password' => '123456']);
            $identifier->signIn();
        }
    ])
    ## identity credential repository
    , new P\AuthSystem\Authenticate\RepoIdentityCredential\IdentityCredentialDigestFile()      // data this provide
    ## to retrieve extra data of user identity
    , new P\AuthSystem\Authenticate\Identity\IdentityFulfillmentLazy(new UserData, 'username') // must fulfilled this
);

// =================================================================================================================

// Identifier To Sign User In/Out
try {
    if (!$authenticator->hasAuthenticated())
        throw new P\AuthSystem\Authenticate\Exceptions\exAccessDenied($authenticator);
} catch (P\AuthSystem\Authenticate\Exceptions\exAuthentication $e) {
    echo '<h1>You MUST Login:</h1>';
    // Challenge User For Credential Login:

    $e->issueException();
}

echo '<h1>Logged In User Data:</h1>';
$identity = $authenticator->hasAuthenticated()->identity();
### now we can get extra data
k(P\Std\cast($identity)->toArray());
```



```php
class UserData implements P\AuthSystem\Authenticate\Interfaces\iProviderIdentityData
    {
        # Finds a user by the given user Identity.
        #
        # @param string $property ie. 'user_name'
        # @param mixed $value ie. 'payam@mail.com'
        #
        # @throws \Exception
        # @return EntityInterface
        #
        function findBy($property, $value)
        {
            $entity = new P\Std\Struct\DataEntity();
            if ($property == 'username' && $value == 'admin')
                ## find by user name
                $entity->import([
                    'email' => 'naderi.payam@gmail.com',
                    'phone' => '+989354323345'
                ]);

            return $entity;
        }
    }

    // Identifier To Sign User In/Out

    $identifier = new P\AuthSystem\Authenticate\Identifier\IdentifierSession('realm_members');
    $identifier->setDefaultIdentity(
        ## identity that provide user data match with credential match identity
        new P\AuthSystem\Authenticate\Identity\IdentityFulfillmentLazy(new UserData, 'username')
    );

    try {
        if (!$identifier->isSignIn())
            throw new P\AuthSystem\Authenticate\Exceptions\exAccessDenied;
    } catch (P\AuthSystem\Authenticate\Exceptions\exAccessDenied $e) {
        echo '<h1>You MUST Loggin:</h1>';
        
        // Challenge User For Credential Login:

        ## credential repository
        $credRepository = new P\AuthSystem\Authenticate\RepoIdentityCredential\IdentityCredentialDigestFile();
        $credRepository
            ->setUsername('admin')
            ->setPassword('123456');

        $match = $credRepository->findIdentityMatch();
        if (!$match)
            die('User/Pass Not Match.');

        // User Authenticated Successfully:
        $identity = $match;

        // Log User IN:
        $identifier->identity()->import($identity);
        $identifier->signIn();
    }

    echo '<h1>Logged In User Data:</h1>';
    $identity = $identifier->identity();

    ### now we can get extra data
    k(P\Std\cast($identity)->toArray());
```
