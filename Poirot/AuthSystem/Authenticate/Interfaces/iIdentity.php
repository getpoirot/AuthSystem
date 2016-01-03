<?php
namespace Poirot\AuthSystem\Authenticate\Interfaces;
use Poirot\Core\Interfaces\iOptionImplement;

/**
 * Represent User Identity and Data
 *
 * [code:]
 *   $identity->getUid();
 *   $identity->getUserEmail(); # extra related data
 * [code]
 *
 */
interface iIdentity extends iOptionImplement
{
    /**
     * Is Identity Full Filled
     *
     * - full filled mean that all needed data
     *   set for this identity.
     *
     *   ! it's usually is enough to have uid
     *
     * @return boolean
     */
    function isFullFilled();

    /**
     * Clean Identity Data
     *
     * @return void
     */
    function clean();
}
