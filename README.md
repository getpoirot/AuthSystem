# Poirot\AuthSystem

authentication & authorization system.

## Overview usage sample

```php
# used with AuthService aggregator
$auth = new AuthService();
$auth->addAuthentication(new DigestFile);
# or with direct adapter
# $auth = new DigestFile; // same action as above
if (!$auth->identity()->hasAuthenticated()) {
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

    $auth->identity()
        ->setRemember()
        ->login();

    echo ('Hello, Dear '.$auth->identity()->hasAuthenticated().' You are authorized ...');

} else {
    echo ('Hello, Dear '.$auth->identity()->hasAuthenticated());
}

die('>_');
```
