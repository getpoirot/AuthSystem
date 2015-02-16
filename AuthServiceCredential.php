<?php
namespace Poirot\Authentication;

use Poirot\Authentication\Interfaces\iAuthorize;
use Poirot\Authentication\Interfaces\iCredential;
use Poirot\Core\OpenOptions;

class AuthServiceCredential extends OpenOptions
    implements
    iCredential
{
    /**
     * @var AuthService
     */
    protected $authService;

    /**
     * On set any property we get authorize service
     * and iterate over registered authService
     * and set credential option if exists on that
     * service
     *
     * @param AuthService $auth
     */
    function injectAuthService(AuthService $auth)
    {
        $this->authService = $auth;
    }

    /**
     * note: We have to override this
     *
     * @param string $key
     * @param mixed $value
     * @return void
     */
    function __set($key, $value)
    {
        // Set Option as Credential Option For Nested Services of AuthService
        /** @var iAuthorize $auth */
        foreach($this->authService->getServices() as $auth)
        {
            // check Credential Fit:
            // - which service credential need this option
            $crd = $auth->credential();
            if (in_array($key, $crd->props()->writable))
                // has this option
                $crd->{$key} = $value;
        }

        // Also Store Option in it:

        $this->properties[$key] = $value;
    }

    /**
     * If Authorization was successful identity
     * will use this to fill user data from
     * adapter to identity
     *
     * ! in database it can be a unique field like
     *   mailAddress, pk, ...
     *
     * @return mixed
     */
    function getUserIdentity()
    {
        // Get User Identity From Nested Services:
        /** @var iAuthorize $auth */
        $userIdentity = false;
        while(
            $auth = $this->authService->getServices()->current()
            && $userIdentity !== false
        )
        {
            $userIdentity = $auth->credential()->getUserIdentity();
            $this->authService->getServices()->next();
        }

        return $userIdentity;
    }
}
 