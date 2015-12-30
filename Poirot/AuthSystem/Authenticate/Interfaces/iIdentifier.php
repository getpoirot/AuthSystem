<?php
namespace Poirot\AuthSystem\Authenticate\Interfaces;
use Poirot\AuthSystem\Authenticate\Exceptions\NotAuthenticatedException;

/**
 * Sign In/Out User as Identity into Storage
 *
 */
interface iIdentifier
{
    /**
     * Inject Identity
     *
     * @param iIdentity $identity Full Filled Identity
     *
     * @throws NotAuthenticatedException Identity not full filled
     * @return $this
     */
    function setIdentity(iIdentity $identity);

    /**
     * Get User Identity
     *
     * @return iIdentity
     */
    function identity();


    /**
     * Login Authenticated User
     *
     * - store current identity data into storage
     * - logout current user if has
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
     * @return void
     */
    function logout();

    /**
     * Has User Logged in?
     *
     * - login mean that user uid exists in the storage
     *
     * note: never check remember flag
     *   the user that authenticated with
     *   Remember Me must recognized when
     *   exists.
     *
     * note: user must be login() to recognize here
     *
     * @return boolean
     */
    function isLogin();
}
