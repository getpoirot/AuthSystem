<?php
namespace Poirot\AuthSystem\Authenticate;

use Poirot\AuthSystem\Authenticate\Interfaces\iIdentity;
use Poirot\Core\OpenOptions;

abstract class AbstractIdentity extends OpenOptions
    implements iIdentity
{
    protected $_t_options__internal = [
        'isFulfilled',
    ];

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
    abstract function isFulfilled();

    /**
     * Clean Identity Data
     *
     * @return void
     */
    function clean()
    {
        foreach($this->props()->writable as $p)
            $this->__unset($p);
    }
}
