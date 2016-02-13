<?php
namespace Poirot\AuthSystem\Authenticate\Interfaces;
use Poirot\Core\Interfaces\iPoirotOptions;

/**
 * Represent User Identity and Data
 *
 * [code:]
 *   $identity->getUid();
 *   $identity->getUserEmail(); # extra related data
 * [code]
 *
 */
interface iIdentity extends iPoirotOptions
{

}
