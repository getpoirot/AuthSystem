<?php
namespace Poirot\AuthSystem\Authenticate;

use Poirot\AuthSystem\Authenticate\Exceptions\exNotAuthenticated;
use Poirot\AuthSystem\Authenticate\Identity\IdentityOpen;
use Poirot\AuthSystem\Authenticate\Interfaces\iIdentifier;
use Poirot\AuthSystem\Authenticate\Interfaces\iIdentity;
use Poirot\Std\SetterBuilderTrait;

abstract class AbstractIdentifier implements iIdentifier
{
    use SetterBuilderTrait;

    const STORAGE_REALM          = 'Default_Auth';
    const STORAGE_IDENTITY_KEY   = 'identity';

    /** @var iIdentity */
    protected $identity;

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
     * @param iIdentity $identity
     *
     * @throws exNotAuthenticated Identity not full filled
     * @return $this
     */
    function setIdentity(iIdentity $identity)
    {
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
        if (!$this->identity)
            $this->identity = $this->getDefaultIdentity();

        if($this->identity->isFulfilled())
            return $this->identity;


        // Attain Identity:
        if ($this->isSignIn()) {
            $identity = $this->attainSignedIdentity();
            if ($identity !== null)
                ## update identity
                $this->identity->from($identity);
        }

        return $this->identity;
    }


    /**
     * Attain Identity Object From Signed Sign
     *
     * !! call when user is signed in to retrieve user identity
     *
     * note: almost retrieve identity data from cache or
     *       storage that store user data. ie. session
     *
     * @see identity()
     * @return iIdentity|null Null if no change need
     */
    abstract function attainSignedIdentity();


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
            $this->realm = self::STORAGE_REALM;

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
            $this->defaultIdentity = new IdentityOpen;

        return $this->defaultIdentity;
    }
}
