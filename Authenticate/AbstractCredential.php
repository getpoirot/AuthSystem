<?php
namespace Poirot\AuthSystem\Authenticate;

use Poirot\AuthSystem\Authenticate\Interfaces\iCredential;

abstract class AbstractCredential implements iCredential
{

    /**
     * Set Options From Array
     *
     * @param array $options Options Array
     *
     * @throws \Exception
     * @return $this
     */
    function fromArray(array $options)
    {
        // TODO: Implement fromArray() method.
    }

    /**
     * Get Properties as array
     *
     * @return array
     */
    function toArray()
    {
        // TODO: Implement toArray() method.
    }

    /**
     * @param string $key
     * @param mixed $value
     * @return void
     */
    function __set($key, $value)
    {
        // TODO: Implement __set() method.
    }

    /**
     * @param string $key
     * @return mixed
     */
    function __get($key)
    {
        // TODO: Implement __get() method.
    }

    /**
     * @param string $key
     * @return bool
     */
    function __isset($key)
    {
        // TODO: Implement __isset() method.
    }

    /**
     * @param string $key
     * @return void
     */
    function __unset($key)
    {
        // TODO: Implement __unset() method.
    }

    /**
     * Set Options
     *
     * @param array|iPoirotOptions|mixed $options
     *
     * @return $this
     */
    function from($options)
    {
        // TODO: Implement from() method.
    }

    /**
     * Set Options From Same Option Object
     *
     * note: it will take an option object instance of $this
     *       OpenOptions only take OpenOptions as argument
     *
     * - also you can check for private and write_only
     *   methods inside Options Object to get fully coincident copy
     *   of Options Class Object
     *
     * @param iOptionImplement $options Options Object
     *
     * @throws \Exception
     * @return $this
     */
    function fromSimilar(/*iOptionImplement*/
        $options)
    {
        // TODO: Implement fromSimilar() method.
    }

    /**
     * Get Options Properties Information
     *
     * @return PropsObject
     */
    function props()
    {
        // TODO: Implement props() method.
    }

    /**
     * Construct
     *
     * @param array|iOptionImplement|mixed $options Options
     */
    function __construct($options = null)
    {
        // TODO: Implement __construct() method.
    }
}