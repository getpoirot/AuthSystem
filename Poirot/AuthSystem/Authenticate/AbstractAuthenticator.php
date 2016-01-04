<?php
namespace Poirot\AuthSystem\Authenticate;

use Poirot\AuthSystem\Authenticate\Authenticator\Adapter\DigestAuthAdapter;
use Poirot\AuthSystem\Authenticate\Exceptions\AuthenticationException;
use Poirot\AuthSystem\Authenticate\Interfaces\iCredential;
use Poirot\AuthSystem\Authenticate\Interfaces\iIdentifier;
use Poirot\AuthSystem\Authenticate\Interfaces\HttpMessageAware\iIdentifier as HttpMessageIdentifier;
use Poirot\AuthSystem\Authenticate\Interfaces\iAuthAdapter;
use Poirot\AuthSystem\Authenticate\Interfaces\iAuthenticator;
use Poirot\AuthSystem\Authenticate\Interfaces\iIdentity;
use Poirot\Core\AbstractOptions;
use Poirot\Core\BuilderSetter;

abstract class AbstractAuthenticator extends BuilderSetter
    implements iAuthenticator
{
    /** @var iAuthAdapter Credential Authenticate Match Adapter (check usr/pas) */
    protected $adapter;

    /** @var iIdentifier|HttpMessageIdentifier */
    protected $identifier;

    // options:
    /** @var iIdentifier|HttpMessageIdentifier */
    protected $default_identifier;


    /**
     * @var array List Setters By Priority
     * [
     *  'service_config',
     *  'listeners',
     *  // ...
     * ]
     *
     * application calls setter methods from top ...
     *
     */
    protected $__setup_array_priority = [
        'default_identifier', ## first set identifier
        'identity'            ## then inject default identity
    ];


    /**
     * Authenticate
     *
     * - authenticate user using credential
     * - login into identifier with iIdentity set from recognized
     *   user data
     *
     * note: after successful authentication, you must call
     *       login() outside of method to store identified user
     *
     * @param mixed $credential \
     * Credential can be extracted from this
     *
     * @throws AuthenticationException|\Exception Or extend of this
     * @return iIdentifier|HttpMessageIdentifier
     */
    function authenticate($credential = null)
    {
        $identity = $this->doAuthenticate($credential);
        if (!$identity instanceof iIdentity && !$identity->isFulfilled())
            throw new AuthenticationException('user authentication failure.');

        $this->identifier()->identity()->from($identity);
        if (!$this->identifier()->identity()->isFulfilled())
            throw new \Exception(
                'User Authenticated Successfully But Identifier Identity Not'
                .' FullFilled Satisfy with That Result.'
            );

        return $this->identifier();
    }

    /**
     * Authenticate user with Credential Data and return
     * FullFilled Identity Instance
     *
     * @param iCredential|mixed $credential \
     * Credential can be extracted from this
     *
     * @throws AuthenticationException Or extend of this
     * @return iIdentity|void
     */
    protected function doAuthenticate($credential = null)
    {
        // do credential extraction on extended
        // ...

        $identity = $this->getAdapter()->doIdentityMatch($credential);
        return $identity;
    }

    /**
     * Has Authenticated And Identifier Exists
     *
     * - it mean that Identifier has full filled identity
     *
     * note: this allow to register this authenticator as a service
     *       to retrieve authenticate information
     *
     * @return boolean
     */
    function hasAuthenticated()
    {
        return $this->identifier()->identity()->isFulfilled();
    }

    /**
     * Get Authenticated User Identifier
     *
     * note: this allow to register this authenticator as a service
     *       to retrieve authenticate information
     *
     * @return iIdentifier|HttpMessageIdentifier
     */
    function identifier()
    {
        if (!$this->identifier)
            $this->identifier = $this->getDefaultIdentifier();

        return $this->identifier;
    }


    // Options:

    /**
     * Set Authentication Adapter
     *
     * @param iAuthAdapter $adapter
     *
     * @return $this
     */
    function setAdapter(iAuthAdapter $adapter)
    {
        $this->adapter = $adapter;
        return $this;
    }

    /**
     * Get Authentication Adapter
     *
     * @return iAuthAdapter
     */
    function getAdapter()
    {
        if (!$this->adapter)
            $this->adapter = new DigestAuthAdapter;

        $this->adapter->setRealm($this->identifier()->getRealm());
        return $this->adapter;
    }

    /**
     * Set Default Identifier Instance
     *
     * @param iIdentifier|HttpMessageIdentifier $identifier
     *
     * @return $this
     */
    function setDefaultIdentifier(iIdentifier $identifier)
    {
        $this->default_identifier = $identifier;
        return $this;
    }

    /**
     * Get Default Identifier Instance
     *
     * @return iIdentifier|HttpMessageIdentifier
     */
    abstract function getDefaultIdentifier();

    /**
     * Helper To Set Default Identity
     * @param iIdentity $identity
     * @return $this
     */
    function setIdentity(iIdentity $identity)
    {
        $this->identifier()->setIdentity($identity);
        return $this;
    }
}
