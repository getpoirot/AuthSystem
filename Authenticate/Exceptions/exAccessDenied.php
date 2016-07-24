<?php
namespace Poirot\AuthSystem\Authenticate\Exceptions;

class exAccessDenied 
    extends exAuthentication
{
    const EXCEPTION_DEFAULT_MESSAGE = 'Access Denied';
}
