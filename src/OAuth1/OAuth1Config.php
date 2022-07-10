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
    protected $oauth_callback = '';

    /**
     * @var string
     * OAuth consumer key.
     */
    protected $oauth_consumer_key = '';

    /**
     * @var string
     * OAuth consumer secret.
     */
    protected $consumer_secret = '';

    /**
     * @var string
     * OAuth realm.
     */
    protected $realm = '';

    /**
     * @var string
     * OAuth access token.
     */
    protected $oauth_token = '';

    /**
     * @var string
     * OAuth token secret.
     */
    protected $token_secret = '';

    /**
     * @var string
     * OAuth verifier.
     */
    protected $oauth_verifier = '';

    /**
     * @param array $oauth_params Associative array of parameters to be set. 
     *              Acceptable params will be set while all others will be discarded.
     * 
     * ```
     * // Valid params
     * $params = [
     *     'oauth_callback' => 'https://test.com/auth',
     *     'oauth_consumer_key' => 'abc123',
     *     'consumer_secret' => 'xyz567',
     *     'realm' => 'Test',
     *     'oauth_token' => 'abc123',
     *     'token_secret' => 'xyz567',
     *     'oauth_verifier' => 'XXXXXXXXXXXXX',
     * ];
     * ```
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

    /**
     * Retrieve all configuration properties in an array.
     * 
     * @return array
     */
    public function getConfigParams()
    {
        return get_object_vars($this);
    }

    /////////////////////////////////
    ////// Getters and Setters /////
    ///////////////////////////////

    /**
     * Get the value of oauth_callback
     *
     * @return  string
     */ 
    public function getOAuthUrl()
    {
        return $this->oauth_callback;
    }

    /**
     * Set the value of oauth_callback
     *
     * @param string $oauth_callback
     */ 
    public function setOAuthUrl(string $oauth_callback)
    {
        $this->oauth_callback = $oauth_callback;
    }

    /**
     * Get the value of consumer_key
     *
     * @return  string
     */ 
    public function getOAuthConsumerKey()
    {
        return $this->oauth_consumer_key;
    }

    /**
     * Set the value of oauth_consumer_key
     *
     * @param string $oauth_consumer_key
     */ 
    public function setOAuthConsumerKey(string $oauth_consumer_key)
    {
        $this->oauth_consumer_key = $oauth_consumer_key;
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
    public function getOAuthToken()
    {
        return $this->oauth_token;
    }

    /**
     * Set OAuth Access token
     *
     * @param string $oauth_token OAuth Access token
     */ 
    public function setOAuthToken(string $oauth_token)
    {
        $this->oauth_token = $oauth_token;
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
    public function getOAuthVerfier()
    {
        return $this->oauth_verifier;
    }

    /**
     * Set OAuth verifier.
     *
     * @param string $oauth_verifier OAuth verifier.
     */ 
    public function setOAuthVerfier(string $oauth_verifier)
    {
        $this->oauth_verifier = $oauth_verifier;
    }
}
