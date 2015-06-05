<?php
namespace Poirot\AuthSystem\Authenticate\Exceptions;

class AccessDeniedException extends AuthenticationException
{
    const EXCEPTION_DEFAULT_MESSAGE = 'Access Denied';
}
 