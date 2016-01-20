<?php
namespace Poirot\AuthSystem\Authenticate\Exceptions;

class BadRequestException extends \RuntimeException
{
    const EXCEPTION_DEFAULT_MESSAGE = 'Bad Request';
    const EXCEPTION_DEFAULT_CODE    = 400;
}
