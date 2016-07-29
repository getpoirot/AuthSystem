<?php
namespace Poirot\AuthSystem\Authenticate\Identifier;

use Poirot\AuthSystem\Authenticate\Exceptions\exAuthentication;
use Poirot\AuthSystem\Authenticate\Exceptions\exNotAuthenticated;
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
    /** @var callable */
    protected $issuer_exception;


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
     * Get Default Identity Instance
     * that Signed data load into
     *
     * @return iIdentity
     */
    abstract protected function _newDefaultIdentity();

    /**
     * Attain Identity Object From Signed Sign
     * exp. session, extract from authorize header,
     *      load lazy data, etc.
     *
     * !! called when user is signed in to retrieve user identity
     *
     * note: almost retrieve identity data from cache or
     *       storage that store user data. ie. session
     *
     * @see withIdentity()
     * @return iIdentity|\Traversable|null Null if no change need
     */
    abstract protected function doRecognizedIdentity();
    
    
    /**
     * Set Immutable Identity
     *
     * @param iIdentity $identity
     *
     * @return $this
     * @throws \Exception immutable error; identity not met requirement
     */
    final function exactIdentity(iIdentity $identity)
    {
        if ($this->identity)
            throw new \Exception('Identity is immutable.');
        
        $defIdentity = $this->_newDefaultIdentity();
        $defIdentity->import($identity);
        if (!$defIdentity->isFulfilled())
            throw new \InvalidArgumentException(sprintf(
                'Identity (%s) not fulfillment (%s).'
                , \Poirot\Std\flatten($identity)
                , \Poirot\Std\flatten($defIdentity)
            ));
        
        $this->identity = $defIdentity;
        return $this;
    }

    /**
     * Get Authenticated User Data Copy
     *
     * - for check that user is signIn the identity must
     *   fulfilled.
     * - if canRecognizeIdentity extract data from it
     *   this cause identity fulfillment with given data
     *   ie. when user exists in session build identity from that
     * 
     * @return iIdentity
     * @throws exNotAuthenticated not set or cant recognized
     */
    final function withIdentity()
    {
        if (!$this->identity && $this->canRecognizeIdentity()) { 
            $identity = $this->doRecognizedIdentity();
            if ($identity)
                ## update identity
                $this->exactIdentity($identity);
        }
        
        if (!$this->identity)
            throw new exNotAuthenticated;

        return clone $this->identity;
    }
    
    /**
     * Issue To Handle Authentication Exception
     *
     * usually called when authentication exception rise
     * to challenge client to login form or something.
     *
     * @param exAuthentication $exception Maybe support for specific error
     *
     * @return void
     */
    final function issueException(exAuthentication $exception = null)
    {
        $callable = ($this->issuer_exception)
            ? $this->issuer_exception
            : $this->doIssueExceptionDefault();
        
        call_user_func($callable, $exception);
    }

    /**
     * Default Exception Issuer
     * @return \Closure
     */
    protected function doIssueExceptionDefault()
    {
        return function($e) {
            // Nothing to do special; just let it go.
            throw $e;
        };
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
            $this->setRealm(self::DEFAULT_REALM);

        return $this->realm;
    }

    /**
     * Set Exception Issuer
     *
     * callable:
     * function(exAuthentication $e)
     * 
     * @param callable $callable
     * 
     * @return $this
     */
    function setIssuerException(/*callable*/ $callable)
    {
        if (!is_callable($callable))
            throw new \InvalidArgumentException(sprintf(
                'Issuer must be callable; given: (%s).'
                , \Poirot\Std\flatten($callable)
            ));
        
        $this->issuer_exception = $callable;
        return $this;
    }
}
