<?php
ini_set('display_errors',1);
ini_set('display_startup_errors',1);
error_reporting(-1);

require_once 'vendor/autoload.php';



//$identity = new Poirot\AuthSystem\Authenticate\BaseIdentity('majid' , ['name'=>'majid']);

$userData = ['name'=>'John' ,
             'password'=>'123456',
             'email'=>'johnDoe@yahoo.com'];

$credentials = new \Poirot\AuthSystem\Authenticate\Adapter\UserPassCredential();
$credentials->setUsername($userData['email'])
            ->setPassword($userData['password']);

$authenticator = new Poirot\AuthSystem\Authenticate\Authenticator($credentials);
//$user = new \Poirot\AuthSystem\Authenticate\AppIdentity('john' , $userData);

$user = $authenticator->authenticate($credentials);

$identifier = new \Poirot\AuthSystem\Authenticate\BaseIdentifier();
$identifier->login($user);

echo '--------------------------------------------------------------';
echo '--------------------------------------------------------------';
echo '--------------------------------------------------------------';
var_dump($user);
echo '--------------------------------------------------------------';
echo '--------------------------------------------------------------';
echo '--------------------------------------------------------------';
var_dump($identifier);
echo '--------------------------------------------------------------';
echo '--------------------------------------------------------------';
echo '--------------------------------------------------------------';
var_dump($_SESSION);
echo '--------------------------------------------------------------';
echo '--------------------------------------------------------------';
echo '--------------------------------------------------------------';
var_dump(new \Poirot\Storage\Adapter\SessionStorage(['ident'=>'salam']));