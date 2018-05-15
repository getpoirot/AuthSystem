<?php
namespace Poirot\AuthSystem\Authenticate\Identity;

use Poirot\AuthSystem\Authenticate\Identity\Traits\tIdentityOfUser;
use Poirot\AuthSystem\Authenticate\Interfaces\iIdentityOfUser;


class IdentityOfUser
    extends aIdentity
    implements iIdentityOfUser
{
    use tIdentityOfUser;

}
