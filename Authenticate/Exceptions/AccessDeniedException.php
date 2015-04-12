<?php
namespace Poirot\AuthSystem\Authenticate\Exceptions;

class AccessDeniedException extends \RuntimeException
{
    const EXCEPTION_ACCESS_DENIED_DEF_MESSAGE = 'Access Denied';

    function __construct(
        $message = self::EXCEPTION_ACCESS_DENIED_DEF_MESSAGE,
        $code = 403,
        \Exception $previous = null
    )
    {
        parent::__construct($message, $code, $previous);
    }
}
 