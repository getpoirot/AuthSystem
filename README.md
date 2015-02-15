# Poirot\Authentication

authentication & authorization system.

## Overview usage sample

```php
$auth = new DigestFile;
if (!$auth->identity()->hasAuthenticated()) {
    try {
        $auth->credential(['username' => 'payam', 'password' => '123456', 'realm' => 'admin'])
            ->authenticate();
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
} else {
    echo ('Hello, Dear '.$auth->identity()->hasAuthenticated().' You are authorized ...');
}
```
