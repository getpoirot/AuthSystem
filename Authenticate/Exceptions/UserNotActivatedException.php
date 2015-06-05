<?php
namespace Poirot\AuthSystem\Authenticate\Exceptions;

class UserNotActivatedException extends AuthenticationException
{
    const EXCEPTION_DEFAULT_MESSAGE = 'User Not Activated';
}
