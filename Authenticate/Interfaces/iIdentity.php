<?php
namespace Poirot\AuthSystem\Authenticate\Interfaces;

interface iIdentity
{
    /**
     * Set Namespace
     *
     * - isolate the authentication process
     *   used by storage to determine owned data
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
     * Set Identified User Id.
     *
     * - it always set from AuthAdapter::authenticate
     * - to complete authorize user login() must call
     *   after each setUserIdent to take effect,
     *   and knowing from hasAuthenticate method.
     *
     * @param mixed $identity User Identity
     *
     * @return $this
     */
    function setUserIdent($identity);

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
     * - if has authenticated user
     *   return identity
     *   else return false
     *
     * - never check remember flag
     *   the user that authenticated with
     *   Remember Me must recognized when
     *   exists.
     *
     * note: user must be login() to recognize here
     *
     * @return false|mixed
     */
    function hasAuthenticated();

    /**
     * Usually when a user recognized as Authenticated
     * user we want to know was session or cookie!!
     *
     * @return boolean
     */
    function isRemembered();
}
