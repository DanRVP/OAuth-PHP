<?php

namespace OAuth\OAuth2;

use OAuth\OAuth;

/**
 * Main class which handles OAuth 2.0 logic
 * @author Dan Rogers
 */
class OAuth2 extends OAuth
{
    /**
     * @var OAuth2Config
     */
    protected $config;

    /////////////////////////////////
    ////// Getters and Setters /////
    ///////////////////////////////

    /**
     * Get the value of config
     *
     * @return OAuth2Config
     */
    public function getConfig()
    {
        parent::getConfig();
    }

    /**
     * Set the value of config
     *
     * @param OAuth2Config $config
     */
    public function setConfig(OAuth2Config $config)
    {
        parent::setConfig($config);
    }
}
