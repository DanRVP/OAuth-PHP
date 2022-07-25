<?php

namespace OAuth\OAuth2;

use OAuth\OAuth;
use OAuth\Utils\OAuthException;

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
    public function setConfig($config)
    {
        if (!($config instanceof OAuth2Config)) {
            throw new OAuthException('Config type must be of OAuth2Config.');
        }

        parent::setConfig($config);
    }
}
