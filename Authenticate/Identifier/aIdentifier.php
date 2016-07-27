<?php
namespace Poirot\AuthSystem\Authenticate\Identifier;

use Poirot\AuthSystem\Authenticate\Identity\IdentityOpen;
use Poirot\AuthSystem\Authenticate\Interfaces\iIdentifier;
use Poirot\AuthSystem\Authenticate\Interfaces\iIdentity;

use Poirot\Std\ConfigurableSetter;

/**
 * Identifier is an object that recognize user in each request
 * or tell that has no recognized user exists.
 * then we can achieve user data with identity that fulfilled with required
 * data.
 *
 * Sign In/Out User as Identity into Environment(by session or something)
 *
 * - if identity is fulfilled/validated means user is recognized
 * - you can sign-in fulfillment identity
 * - sign-in/out take control of current identifier realm
 * - sign in some cases can be happen on request/response headers
 *
 */
abstract class aIdentifier
    extends ConfigurableSetter
    implements iIdentifier
{
    const DEFAULT_REALM          = 'Default_Auth';
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
     * @param string             $realm   Authentication Realm/Domain
     * @param array|\Traversable $options
     */
    function __construct($realm = self::DEFAULT_REALM, $options = null)
    {
        parent::__construct($options);
        $this->setRealm($realm);
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
            $this->identity = $this->_newDefaultIdentity();

        if($this->identity->isFulfilled())
            return $this->identity;


        // Attain Identity:
        if ($this->canRecognizeIdentity()) {
            $identity = $this->doRecognizedIdentity();
            if ($identity !== null)
                ## update identity
                $this->identity->import($identity);
        }

        return $this->identity;
    }


    /**
     * Attain Identity Object From Signed Sign
     * exp. session, extract from authorize header,
     *      load lazy data, etc.
     *
     * !! call when user is signed in to retrieve user identity
     *
     * note: almost retrieve identity data from cache or
     *       storage that store user data. ie. session
     *
     * @see identity()
     * @return iIdentity|\Traversable|null Null if no change need
     */
    abstract protected function doRecognizedIdentity();


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
            $this->setRealm(self::DEFAULT_REALM);

        return $this->realm;
    }


    // Options:

    /**
     * Get Default Identity Instance
     * that Signed data load into
     *
     * @return iIdentity
     */
    protected function _newDefaultIdentity()
    {
        return new IdentityOpen;
    }
}
