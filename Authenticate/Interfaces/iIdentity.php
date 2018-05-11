<?php
namespace Poirot\AuthSystem\Authenticate\Interfaces;

use Poirot\Std\Interfaces\Struct\iDataOptions;


/**
 * Represent User Identity and Data
 *
 * [code:]
 *   $identity->getUid();
 *   $identity->getUserEmail(); # extra related data
 * [code]
 *
 */
interface iIdentity 
    extends iDataOptions
{ }
