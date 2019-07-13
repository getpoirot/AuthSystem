<?php
namespace Poirot\AuthSystem\Authenticate\Exceptions;

class AccessDeniedError
    extends AuthenticationError
{
    const EXCEPTION_DEFAULT_MESSAGE = 'Access Denied';
}
