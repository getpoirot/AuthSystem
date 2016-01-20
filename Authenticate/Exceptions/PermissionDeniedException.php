<?php
namespace Poirot\AuthSystem\Authenticate\Exceptions;

class PermissionDeniedException extends AuthenticationException
{
    const EXCEPTION_DEFAULT_MESSAGE = 'Access Denied';
}
 