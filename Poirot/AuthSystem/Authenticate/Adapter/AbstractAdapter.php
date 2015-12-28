<?php
namespace Poirot\AuthSystem\Authenticate\Adapter;

use Poirot\AuthSystem\Authenticate\Interfaces\iAuthenticateAdapter;
use Poirot\AuthSystem\Authenticate\Interfaces\iCredential;
use Poirot\AuthSystem\Authenticate\Interfaces\iIdentity;
use Poirot\Core\AbstractOptions;
use Poirot\Core\BuilderSetterTrait;

abstract class AbstractAdapter implements iAuthenticateAdapter
{
    use BuilderSetterTrait;

    /**
     * @var iCredential
     */
    protected $credential;

    /**
     * @var iIdentity
     */
    protected $identity;

    /**
     * Construct
     *
     * ! if namespace not set use class name instead
     *
     * @param iIdentity|array $identRoptions Identity Object Or Array Setter Options
     */
    function __construct(/*iIdentity*/ $identRoptions = null)
    {
        if ($identRoptions === null)
            return;

        if (! $identRoptions instanceof iIdentity && ! is_array($identRoptions))
            throw new \InvalidArgumentException(sprintf(
                'Construct argument must be instance of iIdentity or array setter options; "%s" given.'
                , is_object($identRoptions) ? get_class($identRoptions) : (gettype($identRoptions).serialize($identRoptions))
            ));

        if (is_array($identRoptions))
            $this->setupFromArray($identRoptions);
        else
            $this->setIdentity($identRoptions);
    }

    /**
     * Authorize
     *
     * - throw exception from Authorize\Exceptions
     *   also you can throw your app meaning exception
     *   like: \App\Auth\UserBannedException
     *   to catch behaves
     *
     * - each time called will clean current storage
     * - after successful authentication, you must call
     *   login() to save identified user
     *
     *   note: for iAuthorizeUserDataAware
     *         it used user data model to retrieve data
     *         on authentication in case of user isActive
     *         and so on ...
     *
     * @throws \Exception
     * @return $this
     */
    abstract function authenticate();

    /**
     * Set Authorized User Identity
     *
     * @param iIdentity $identity
     *
     * @return $this
     */
    function setIdentity(iIdentity $identity)
    {
        $this->identity = $identity;

        return $this;
    }

    /**
     * Get Authorized User Identity
     *
     * - when we have empty identity
     *   it means we have not authorized yet
     *
     * ! don't use default identity creation on get if not
     *   any identity available
     *
     *   identities must inject into adapter by auth services
     *
     * @throws \Exception No Identity Available Or Set
     * @return iIdentity
     */
    function getIdentity()
    {
        if (!$this->identity)
            throw new \Exception('No Identity Object Available Or Set.');

        return $this->identity;
    }

    /**
     * Credential
     *
     * - it`s contains credential fields used by
     *   authorize() to authorize user.
     *   maybe, user/pass or ip address in some case
     *   that we want auth. user by ip
     *
     * - it may be vary from within different Authorize
     *   services
     *
     * @param null|array|AbstractOptions $options Builder Options
     *
     * @return $this|iCredential
     */
    function credential($options = null)
    {
        if (!$this->credential)
            $this->credential = $this->insCredential();

        if ($options !== null) {
            $this->credential->from($options);
            // $auth->credential(['usr' => 'payam', 'psw' => '***'])
            //    ->authorize();
            return $this; // <==
        }

        return $this->credential;
    }

    /**
     * Get Instance of credential Object
     *
     * @return iCredential
     */
    protected abstract function insCredential();
}
