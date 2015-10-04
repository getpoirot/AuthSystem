<?php
namespace Poirot\AuthSystem\Authenticate\Exceptions;

class AuthenticationException extends \RuntimeException
{
    const EXCEPTION_DEFAULT_MESSAGE = 'Authentication Failed';

    function __construct(
        $message = self::EXCEPTION_DEFAULT_MESSAGE,
        $code = 403,
        \Exception $previous = null
    )
    {
        parent::__construct($message, $code, $previous);
    }
}
 