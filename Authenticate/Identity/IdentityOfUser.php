<?php
namespace Poirot\AuthSystem\Authenticate\Identity;

use Poirot\AuthSystem\Authenticate\Interfaces\iIdentityOfUser;


class IdentityOfUser
    extends aIdentity
    implements iIdentityOfUser
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
    function setData(array $data)
    {
        $this->data = $data;
        return $this;
    }

    /**
     * Data Embed With User Identity
     *
     * @return array
     */
    function getMetaData()
    {
        return $this->data;
    }
}
