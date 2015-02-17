<?php
namespace Poirot\AuthSystem\Authenticate\Adapter;

use Poirot\AuthSystem\Authenticate\Interfaces\iAuthenticateAdapter;
use Poirot\AuthSystem\Authenticate\Interfaces\iCredential;
use Poirot\AuthSystem\Authenticate\Interfaces\iIdentity;
use Poirot\AuthSystem\BaseIdentity;
use Poirot\Core\AbstractOptions;

abstract class AbstractAdapter implements iAuthenticateAdapter
{
    /**
     * @var iCredential
     */
    protected $credential;

    /**
     * @var BaseIdentity
     */
    protected $identity;

    /**
     * use class name if null
     * @var string
     */
    protected $namespace = null;

    /**
     * Construct
     *
     * ! if namespace not set use class name instead
     *
     * @param null|string $namespace Namespace
     */
    function __construct($namespace = null)
    {
        if ($namespace !== null)
            $this->setNamespace($namespace);
    }

    /**
     * Change Authorization Namespace
     *
     * - isolate the authentication process
     *   used by storage to determine owned data
     *
     * @param string $namespace
     *
     * @return $this
     */
    function setNamespace($namespace)
    {
        $this->namespace = (string) $namespace;

        return $this;
    }

    /**
     * Get Namespace
     *
     * @return string
     */
    function getCurrNamespace()
    {
        if ($this->namespace === null)
            $this->setNamespace(get_class($this));

        return $this->namespace;
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
     * Authorized User Identity
     *
     * - when ew have empty identity
     *   it means we have not authorized yet
     *
     * note: make sure namespace on identity always match
     *       with this
     *
     * @return iIdentity
     */
    function identity()
    {
        if (!$this->identity)
            $this->identity = new BaseIdentity($this->getCurrNamespace());

        $this->identity->setNamespace($this->getCurrNamespace());

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
            return $this;
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
