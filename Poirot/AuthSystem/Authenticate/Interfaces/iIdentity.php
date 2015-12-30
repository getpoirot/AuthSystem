<?php
namespace Poirot\AuthSystem\Authenticate\Interfaces;

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
{
    /**
     * Set User Unique Identifier
     *
     * - usually full fill this identity when uid set
     *
     * @param string $uid User Unique ID
     *
     * @return $this
     */
    function setUid($uid);

    /**
     * Get User Unique Identifier
     *
     * @return string
     */
    function getUid();


    // ...

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
}
