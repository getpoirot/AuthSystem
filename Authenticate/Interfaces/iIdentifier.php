<?php
namespace Poirot\AuthSystem\Authenticate\Interfaces;

/**
 * Log an Identity of User Into Environment
 *
 */

interface iIdentifier
{
    /**
     * Inject Identity
     *
     * @param iIdentity $identity
     *
     * @return $this
     */
    function setIdentity(iIdentity $identity);

    /**
     * Login Authenticated User
     *
     * - store current identity data into storage
     *
     * @throws \Exception no identity defined
     * @return $this
     */
    function login();

    /**
     * Logout Authenticated User
     *
     * - it must destroy storage data
     *
     * @return $this
     */
    function logout();


    /**
     * Has User Logged in?
     *
     * note: never check remember flag
     *   the user that authenticated with
     *   Remember Me must recognized when
     *   exists.
     *
     * note: user must be login() to recognize here
     *
     * @return false|mixed
     */
    function isLogin();

    /**
     * Get User Identity
     *
     * - if user has logged in get identity from
     *   storage otherwise return null
     *
     * @return null|iIdentity
     */
    function withIdentity();
}
