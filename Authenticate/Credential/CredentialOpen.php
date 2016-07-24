<?php
namespace Poirot\AuthSystem\Authenticate\Credential;

use Poirot\AuthSystem\Authenticate\Interfaces\iCredential;
use Poirot\Std\Struct\DataOptionsOpen;

/**
 * Credential used by authenticator to authenticate user
 * usually checked against storage data like mysql, etc.
 *
 * - it`s contains credential fields used by
 *   authorize() to authorize user.
 *   maybe, user/pass or ip address in some case
 *   that we want auth. user by ip
 *
 * - it may be vary from within different Authorize
 *   services
 *
 * [code:]
 *   $credential
 *      ->setUsername('user_name')
 *      ->setPassword('*******)
 *   ;
 * [code]
 */

class CredentialOpen
    extends DataOptionsOpen
    implements iCredential
{ }
