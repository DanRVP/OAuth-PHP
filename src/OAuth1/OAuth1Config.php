<?php

namespace OAuth\OAuth1;

/**
 * Config object for OAuth 1.0 requests. 
 * @author Dan Rogers
 */
class OAuth1Config
{
    /**
     * @var string
     * OAuth callback URL.
     */
    protected $callback_url;

    /**
     * @var string
     * OAuth consumer key.
     */
    protected $consumer_key;

    /**
     * @var string
     * OAuth consumer secret.
     */
    protected $consumer_secret;

    /**
     * @var string
     * OAuth realm.
     */
    protected $realm;

    /**
     * @var string
     * OAuth access token.
     */
    protected $access_token;

    /**
     * @var string
     * OAuth token secret.
     */
    protected $token_secret;

    /**
     * @var string
     * OAuth verifier.
     */
    protected $verifier;

    /**
     * @param array $oauth_params Associative array of parameters to be set. 
     *              Acceptable params will be set while all others will be discarded.
     */
    public function __construct(array $oauth_params)
    {
        $valid_parameters = array_keys(get_object_vars($this));
        foreach ($oauth_params as $key => $value) {
            if (in_array($key, $valid_parameters)) {
                $this->$key = $value;
            }
        }
    }

    /////////////////////////////////
    ////// Getters and Setters /////
    ///////////////////////////////

    /**
     * Get the value of callback_url
     *
     * @return  string
     */ 
    public function getCallbackUrl()
    {
        return $this->callback_url;
    }

    /**
     * Set the value of callback_url
     *
     * @param string $callback_url
     */ 
    public function setCallbackUrl(string $callback_url)
    {
        $this->callback_url = $callback_url;
    }

    /**
     * Get the value of consumer_key
     *
     * @return  string
     */ 
    public function getConsumerKey()
    {
        return $this->consumer_key;
    }

    /**
     * Set the value of consumer_key
     *
     * @param string $consumer_key
     */ 
    public function setConsumerKey(string $consumer_key)
    {
        $this->consumer_key = $consumer_key;
    }

    /**
     * Get the value of consumer_secret
     *
     * @return  string
     */ 
    public function getConsumerSecret()
    {
        return $this->consumer_secret;
    }

    /**
     * Set the value of consumer_secret
     *
     * @param string $consumer_secret
     */ 
    public function setConsumerSecret(string $consumer_secret)
    {
        $this->consumer_secret = $consumer_secret;
    }

    /**
     * Get OAuth realm
     *
     * @return string
     */ 
    public function getRealm()
    {
        return $this->realm;
    }

    /**
     * Set OAuth realm
     *
     * @param string $realm OAuth realm
     */ 
    public function setRealm(string $realm)
    {
        $this->realm = $realm;
    }

    /**
     * Get OAuth Access token
     *
     * @return string
     */ 
    public function getAccessToken()
    {
        return $this->access_token;
    }

    /**
     * Set OAuth Access token
     *
     * @param string $access_token OAuth Access token
     */ 
    public function setAccessToken(string $access_token)
    {
        $this->access_token = $access_token;
    }

    /**
     * Get OAuth token secret.
     *
     * @return string
     */ 
    public function getTokenSecret()
    {
        return $this->token_secret;
    }

    /**
     * Set OAuth token secret.
     *
     * @param string $token_secret OAuth token secret.
     */ 
    public function setTokenSecret(string $token_secret)
    {
        $this->token_secret = $token_secret;
    }

    /**
     * Get OAuth verifier.
     *
     * @return string
     */ 
    public function getVerfier()
    {
        return $this->verifier;
    }

    /**
     * Set OAuth verifier.
     *
     * @param string $verifier OAuth verifier.
     */ 
    public function setVerfier(string $verifier)
    {
        $this->verifier = $verifier;
    }
}
