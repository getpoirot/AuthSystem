<?php
namespace Poirot\Authentication\Adapter;

use Poirot\Authentication\Interfaces\iAuthorize;
use Poirot\Authentication\Interfaces\iIdentity;
use Poirot\Core\AbstractOptions;

class DigestFile implements iAuthorize
{
    /**
     * @var DigestFileCredential
     */
    protected $credential;

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
    function toNamespace($namespace)
    {
        // TODO: Implement toNamespace() method.
    }

    /**
     * Get Namespace
     *
     * @return string
     */
    function getCurrNamespace()
    {
        // TODO: Implement getCurrNamespace() method.
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
     * @return $this|DigestFileCredential
     */
    function credential($options = null)
    {
        if (!$this->credential)
            $this->credential = new DigestFileCredential;

        if ($options !== null) {
            $this->credential->from($options);
            // $auth->credential(['usr' => 'payam', 'psw' => '***'])
            //    ->authorize();
            return $this;
        }

        return $this->credential;
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
     * - after successful authentication it will fill
     *   the identity
     *   note: for iAuthorizeUserDataAware
     *         it used user data model to retrieve data
     *
     * @throw \Exception
     * @return $this
     */
    function authorize()
    {
        // TODO: Implement authorize() method.
    }

    /**
     * Authorized User Identity
     *
     * - when ew have empty identity
     *   it means we have not authorized yet
     *
     * @return iIdentity
     */
    function identity()
    {
        // TODO: Implement identity() method.
    }
}
 