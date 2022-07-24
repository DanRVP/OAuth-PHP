<?php

namespace OAuth;

class OAuth
{
    /**
     * @param OAuthConfig $config
     */
    public function __construct($config)
    {
        $this->setConfig($config);
    }

    /////////////////////////////////
    ////// Getters and Setters /////
    ///////////////////////////////

    /**
     * Get the value of config
     *
     * @return OAuthConfig
     */
    public function getConfig()
    {
        return $this->config;
    }

    /**
     * Set the value of config
     *
     * @param OAuthConfig $config
     */
    public function setConfig($config)
    {
        $this->config = $config;
    }
}