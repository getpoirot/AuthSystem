<?php
namespace Poirot\Authentication\Interfaces;

interface iIdentity
{
    /**
     * Set Namespace
     *
     * @param string $namespace
     *
     * @return $this
     */
    function setNamespace($namespace);

    /**
     * Get Namespace
     *
     * @return string
     */
    function getNamespace();

    /**
     * Set User Identity
     *
     * - it always set from AuthService::authorize
     *   found with AuthService::credential::getUserIdentity
     *
     * @param mixed $identity User Identity
     *
     * @return $this
     */
    function setUserIdentity($identity);

    /**
     * Get User Identity
     *
     * @return mixed
     */
    function getUserIdentity();

    /**
     * Login Authorized User
     *
     * @return $this
     */
    function login();

    /**
     * Remember Me Feature!
     *
     * @param bool $flag
     *
     * @return $this
     */
    function setRemember($flag = true);

    /**
     * Clear Credential Entry
     *
     * - it must clear storage data
     * - it must destroy persist code
     *
     * @return $this
     */
    function logout();

    /**
     * Has Authenticated User?
     *
     * @return boolean
     */
    function hasAuthenticated();
}
