<?php
namespace Poirot\AuthSystem\Authenticate\Interfaces;

interface iIdentifier
{
    /**
     * Login Authenticated User
     *
     * - store current identity data into storage
     *
     * @param iIdentity $identity
     *
     * @return $this
     */
    function login(iIdentity $identity);

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
    function identity();


    /**
     * __getStorage
     *
     * returns the storage object which this identifier
     * object is working with
     * @return mixed
     */
    function __getStorage();
}
