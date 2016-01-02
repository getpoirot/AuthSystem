<?php
namespace Poirot\AuthSystem\Authenticate;

use Poirot\AuthSystem\Authenticate\Exceptions\NotAuthenticatedException;
use Poirot\AuthSystem\Authenticate\Interfaces\iIdentifier;
use Poirot\AuthSystem\Authenticate\Interfaces\iIdentity;
use Poirot\Core\BuilderSetterTrait;

abstract class AbstractIdentifier implements iIdentifier
{
    use BuilderSetterTrait;

    const REALM = 'Poirot_Auth_Identifier';

    /** @var iIdentity */
    protected $identity;

    /** @var boolean Remember user when login */
    protected $_remember = false;

    // options:
    /** @var iIdentity */
    protected $defaultIdentity;
    protected $realm;

    /**
     * Construct
     *
     * @param array|null $options
     */
    function __construct(array $options = null)
    {
        if ($options !== null)
            $this->setupFromArray($options);
    }

    /**
     * Inject Identity
     *
     * @param iIdentity $identity Full Filled Identity
     *
     * @throws NotAuthenticatedException Identity not full filled
     * @return $this
     */
    function setIdentity(iIdentity $identity)
    {
        if (!$identity->isFullFilled())
            throw new NotAuthenticatedException;

        $this->identity = $identity;
        return $this;
    }

    /**
     * Get Authenticated User Data
     *
     * - if identity exists use it
     * - otherwise if signIn extract data from it
     *   ie. when user exists in session build identity from that
     *
     * - not one of above situation return empty identity
     *
     * @return iIdentity
     */
    function identity()
    {
        if($this->identity)
            return $this->identity;


        // Attain Identity:
        if ($this->isSignIn())
            $identity = $this->attainSignedIdentity();
        else
            $identity = $this->getDefaultIdentity();

        return $this->identity = $identity;
    }


    /**
     * Attain Identity Object From Signed Sign
     * @see identity()
     * @return iIdentity
     */
    abstract function attainSignedIdentity();


    // ...

    /**
     * Remember Me Feature!
     *
     * @param bool $flag
     *
     * @return $this
     */
    function setRemember($flag = true)
    {
        $this->_remember = $flag;
        return $this;
    }


    // Options:

    /**
     * Set Realm To Limit Authentication
     *
     * ! mostly used as storage namespace to have
     *   multiple area for each different Authenticate system
     *
     * @param string $realm
     *
     * @return $this
     */
    function setRealm($realm)
    {
        $this->realm = (string) $realm;
        return $this;
    }

    /**
     * Get Realm Area
     *
     * @return string
     */
    function getRealm()
    {
        if (!$this->realm)
            $this->realm = self::REALM;

        return $this->realm;
    }

    /**
     * Set Default Identity Instance
     * @param iIdentity $identity
     * @return $this
     */
    function setDefaultIdentity(iIdentity $identity)
    {
        $this->defaultIdentity = $identity;
        return $this;
    }

    /**
     * Get Default Identity Instance
     * @return iIdentity
     */
    function getDefaultIdentity()
    {
        if (!$this->defaultIdentity)
            $this->defaultIdentity = new BaseIdentity;

        return $this->defaultIdentity;
    }
}
