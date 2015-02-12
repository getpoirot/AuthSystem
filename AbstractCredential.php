<?php
namespace Poirot\Authentication;

use Poirot\Authentication\Interfaces\iCredential;
use Poirot\Core\AbstractOptions;

abstract class AbstractCredential extends AbstractOptions
    implements
    iCredential
{
    /**
     * Used For Remember Me! Feature
     * @var bool
     */
    protected $remember = false;

    /**
     * Remember Me Feature!
     *
     * @param bool $flag
     *
     * @return $this
     */
    function setRemember($flag = true)
    {
        $this->remember = $flag;

        return $this;
    }

    /**
     * If Authorization was successful identity
     * will use this to fill user data from
     * adapter to identity
     *
     * ! in database it can be a unique field like
     *   mailAddress, pk, ...
     *
     * @return mixed
     */
    abstract function getUserIdentity();
}
 