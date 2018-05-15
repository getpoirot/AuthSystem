<?php
namespace Poirot\AuthSystem\Authenticate\Identity\Traits;


trait tIdentityOfUser
{
    protected $ownerId;
    protected $data = [];


    /**
     * Set Owner Id
     *
     * @param mixed $ownerId
     *
     * @return $this
     */
    function setOwnerId($ownerId)
    {
        $this->ownerId = $ownerId;
        return $this;
    }

    /**
     * Get User Unique Id
     *
     * @return mixed
     */
    function getOwnerId()
    {
        return $this->ownerId;
    }

    /**
     * Set Meta Data Embed
     *
     * @param array $data
     *
     * @return $this
     */
    function setMetaData(array $data = null)
    {
        $this->data = $data;
        return $this;
    }

    /**
     * Data Embed With User Identity
     *
     * @param string $key
     *
     * @return array
     */
    function getMetaData($key = null)
    {
        $data = $this->data;
        if ($key !== null)
            $data = ( isset($data[$key]) ) ? $data[$key] : null;


        return $data;
    }
}
