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
            // change auth namespaces same as this class
            // TODO maybe need clone object
            $namespace = $this->identity()->getNamespace();
            $auth->identity()->setNamespace($namespace);

            $auth->authenticate();
        }

        // No Exception Happens During Authentication:
        // we have to own user identity on this class
        $this->identity()->setUserIdent($oldIdentity);

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
 