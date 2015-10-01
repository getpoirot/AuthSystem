# Poirot\AuthSystem

authentication & authorization system.

## Overview usage sample

```php
# used with AuthService aggregator
$auth = new AggrAuthAdapter(new BaseIdentity('admin.users'));
$auth->addAuthentication(new DigestFileAuthAdapter);
# or with direct adapter
# $auth = new DigestFile; // same action as above
if (!$auth->getIdentity()->hasAuthenticated()) {
    try {
        $auth->credential([
            'username' => 'payam'
            , 'password' => '123456'
            , 'realm' => 'admin'
        ])->authenticate();
    } catch (WrongCredentialException $e) {
        throw new \Exception('Invalid Username or Password.');
    } catch (UserNotFoundException $e) {
        throw new \Exception('Invalid Username or Password.');
    } catch (\Exception $e)
    {
        throw $e;
    }

    $auth->getIdentity()
        ->setRemember()
        ->login();

    echo ('Hello, Dear '.$auth->getIdentity()->hasAuthenticated().' You are authorized ...');

} else {
    echo ('Hello, Dear '.$auth->getIdentity()->hasAuthenticated());
}

die('>_');
```

## TODO

- Write Authentication Service Layer On Top Of Adapters For Application Dispatching Control 
