<?php

namespace OAuth\OAuth1;

use OAuth\Utils\OAuthException;

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
     * @var string
     * OAuth signature method.
     */
    protected $oauth_signature_method = self::HMAC_SHA1;

    /**
     * @param array $oauth_params Associative array of parameters to be set.
     *              Acceptable params will be set while all others will be discarded.
     *              (Think of it as akin to Python's kwargs)
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
     *     'oauth_signature_method' => self::HMAC_SHA1,
     * ];
     * ```
     */
    public function __construct(array $oauth_params)
    {
        $valid_parameters = array_keys(get_object_vars($this));
        foreach ($oauth_params as $key => $value) {
            if (in_array($key, $valid_parameters)) {
                $setter_name = $this->getSetterName($key);
                $this->$setter_name($value);
            }
        }
    }

    /**
     * Retrieve properties used in the header and signature.
     *
     * @return array
     */
    public function getHeaderParams()
    {
        $params = [
            'oauth_callback' => $this->getOauthCallback(),
            'oauth_consumer_key' => $this->getOauthConsumerKey(),
            'oauth_token' => $this->getOauthToken(),
            'oauth_verifier' => $this->getOauthVerifier(),
            'oauth_signature_method' => $this->getOauthSignatureMethod(),
        ];

        // Remove empty fields
        return array_filter($params);
    }

    /**
     * Get the name of a setter for the property.
     *
     * Property naming convention is `snake_case`.
     * Method naming convention is `set + PascalisedPropertyName` which in
     * effect makes it `camelCase`.
     *
     * For example property `oauth_signature_method` becomes `setOauthSignature`.
     */
    private function getSetterName($property)
    {
        $parts = explode('_', $property);
        $pascalised = array_map('ucfirst', $parts);
        return 'set' . implode('', $pascalised);
    }

    /////////////////////////////////
    ////// Getters and Setters /////
    ///////////////////////////////

    /**
     * Get the value of oauth_callback
     *
     * @return  string
     */
    public function getOauthCallback()
    {
        return $this->oauth_callback;
    }

    /**
     * Set the value of oauth_callback
     *
     * @param string $oauth_callback
     */
    public function setOauthCallback(string $oauth_callback)
    {
        $this->oauth_callback = $oauth_callback;
    }

    /**
     * Get the value of consumer_key
     *
     * @return  string
     */
    public function getOauthConsumerKey()
    {
        return $this->oauth_consumer_key;
    }

    /**
     * Set the value of oauth_consumer_key
     *
     * @param string $oauth_consumer_key
     */
    public function setOauthConsumerKey(string $oauth_consumer_key)
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
    public function getOauthToken()
    {
        return $this->oauth_token;
    }

    /**
     * Set OAuth Access token
     *
     * @param string $oauth_token OAuth Access token
     */
    public function setOauthToken(string $oauth_token)
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
    public function getOauthVerifier()
    {
        return $this->oauth_verifier;
    }

    /**
     * Set OAuth verifier.
     *
     * @param string $oauth_verifier OAuth verifier.
     */
    public function setOauthVerifier(string $oauth_verifier)
    {
        $this->oauth_verifier = $oauth_verifier;
    }

    /**
     * Get OAuth signature method.
     *
     * @return string
     */
    public function getOauthSignatureMethod()
    {
        return $this->oauth_signature_method;
    }

    /**
     * Set OAuth signature method.
     *
     * @param string $oauth_signature_method  OAuth signature method.
     * @throws OAuthException
     */
    public function setOauthSignatureMethod(string $oauth_signature_method)
    {
        if (!in_array($oauth_signature_method, self::VALID_SIGNATURE_METHODS)) {
            $methods = implode(', ', self::VALID_SIGNATURE_METHODS);
            throw new OAuthException("Currently supported signature methods are: $methods.");
        }

        $this->oauth_signature_method = $oauth_signature_method;
    }

    /////////////////////////////////
    /////////// Constants //////////
    ///////////////////////////////

    // Hmac constants
    const HMAC_SHA1 = 'HMAC-SHA1';
    const HMAC_SHA256 = 'HMAC-SHA256';
    const HMAC_SHA512 = 'HMAC-SHA512';
    const VALID_SIGNATURE_METHODS = [
        self::HMAC_SHA1,
        self::HMAC_SHA256,
        self::HMAC_SHA512
    ];

    // Used to define the method which `hash_hmac()` should use to encode.
    const HMAC_METHOD_MAP = [
        self::HMAC_SHA1 => 'sha1',
        self::HMAC_SHA256 => 'sha256',
        self::HMAC_SHA512 => 'sha512',
    ];
}
