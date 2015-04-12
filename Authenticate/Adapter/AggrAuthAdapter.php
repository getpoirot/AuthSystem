<?php
namespace Poirot\AuthSystem\Authenticate\Adapter;

use Poirot\AuthSystem\Authenticate\Interfaces\iAuthenticateAdapter;
use Poirot\AuthSystem\Authenticate\Interfaces\iCredential;
use Poirot\Core\AbstractOptions;

/**
 * Authentication Aggregate Service
 *
 */
class AggrAuthAdapter extends AbstractAdapter
{
    /**
     * @var \SplPriorityQueue
     */
    protected $queue;

    /**
     * Insert Authentication Service
     *
     * @param iAuthenticateAdapter $auth
     * @param int $priority
     *
     * @return $this
     */
    function addAuthentication(iAuthenticateAdapter $auth, $priority = 10)
    {
        $auth->setNamespace($this->getCurrNamespace());

        $this->__queue()
            ->insert($auth, $priority);

        return $this;
    }

    /**
     * we need registered services
     * on AuthServiceCredential
     *
     * @return \SplPriorityQueue
     */
    function getServices()
    {
        return clone $this->__queue();
    }

    /**
     * Get PriorityQueue
     *
     * @return \SplPriorityQueue
     */
    protected function __queue()
    {
        if (!$this->queue)
            $this->queue = new \SplPriorityQueue();

        return $this->queue;
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
        /** @var iAuthenticateAdapter $auth */
        foreach(clone $this->__queue() as $auth)
            $auth->setNamespace($namespace);

        return parent::setNamespace($namespace);
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
    function authenticate()
    {
        /** @var iAuthenticateAdapter $auth */
        $oldIdentity = '___notSetYet!___';
        foreach($this->getServices() as $auth) {
            $auth->authenticate();
            $identity = $auth->identity()->getUserIdentity();
            if ($oldIdentity === '___notSetYet!___')
                $oldIdentity = $identity;
            elseif ($oldIdentity !== $identity)
                throw new \Exception(
                    'User Identity has changed during authentication. it`s unexpected behavior'
                );
        }

        // No Exception Happens During Authentication:
        // we have to own user identity on this class
        $this->identity()->setUserIdentity($oldIdentity);

        return $this;
    }

    /**
     * Get Instance of credential Object
     *
     * @return iCredential
     */
    protected function insCredential()
    {
        $insCredential = new AggrAuthCredential();
        $insCredential->injectAuthService($this);

        return $insCredential;
    }
}
 