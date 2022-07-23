<?php

namespace OAuth\OAuth1;

use OAuth\Utils\OAuthHelper;
use OAuth\Utils\RsaPrivateKey;

/**
 * Main class which handles OAuth 1.0 logic
 * @author Dan Rogers
 */
class OAuth1
{
    /**
     * @var OAuth1Config
     */
    protected $config;

    /**
     * @var string
     * The generated base string.
     * Read-only for debugging.
     */
    protected $base_string;

    /**
     * @var string
     * The generated signature.
     * Read-only for debugging.
     */
    protected $signature;

    /**
     * @param OAuth1Config $config
     */
    public function __construct(OAuth1Config $config)
    {
        $this->setConfig($config);
    }

    /**
     * Generate an OAuth 1.0 Authorization header string based on the current
     * config and any extra parameters specified by the user.
     *
     * @param string $url The URL to query.
     * @param string $method The HTTP method being used.
     * @param array $extra_params Any extra parameters to be included in the
     *              request. These should only be included if they are part
     *              of any x-www-form-urlencoded data in the request.
     */
    public function generateAuthorization(string $url, string $method, array $extra_params = [])
    {
        $oauth_params = $this->config->getHeaderParams();
        $request_params = array_merge($oauth_params, $extra_params);
        $request_params['oauth_timestamp'] = OAuthHelper::getTimestamp();
        $request_params['oauth_nonce'] = OAuthHelper::generateRandomString(20);
        $request_params['oauth_signature'] = $this->buildOauthSignature();

        return $this->buildOauthHeader($request_params);
    }

    private function buildOauthSignature()
    {
        $signature_method = $this->config->getOauthSignatureMethod();
        $signature_type = $this->determineSignatureMethodType($signature_method);

        // Probably an invalid signature type. 
        if (empty($signature_type)) {
            throw new OAuthException('Invalid signature type: ' . $signature_method);
        }

        $base_string = $this->buildBaseString($method, $url, $params);
        $signature = '';

        if ($signature_type === OAuth1Config::HMAC) {
            $signature = $this->hmacSignature($base_string);
        } else if ($signature_type === OAuth1Config::RSA) {
            $signature = $this->rsaSignature($base_string);
        } else if ($signature_type === OAuth1Config::PLAINTEXT) {
            // TODO add plaintext signature.
        }

        return $signature;
    }

    /**
     * Builds the OAuth 1.0 Authorization header.
     *
     * @param array $params Array of parameters used to create signature.
     * @return string The OAuth header
     */
    private function buildOauthHeader(array $params)
    {
        $header = 'OAuth ';

        $realm = $this->config->getRealm();
        if (!empty($realm)) {
            $header .= 'realm=' . $this->config->getRealm() . '", ';
        }

        foreach ($params as $key => $value) {
            $header_element = $key . '="' . rawurlencode($value) . '", ';
            $header .= $header_element;
        }

        return rtrim(trim($header), ',');
    }

    /**
     * Generates a base string to be used when building an OAuth signature.
     *
     * @param string $http_method HTTP method of the request.
     * @param string $url Url of the request.
     * @param array $params An array of parameters used to build the string.
     * @return string A base string to be used in OAuth signature generation.
     */
    private function buildBaseString(string $http_method, string $url, array $params){
        //http method must be upper case
        $base_string = strtoupper($http_method) . '&';
        $base_string .= rawurlencode($url) . '&';

        //all parameters must be alphabetically sorted
        ksort($params);

        $param_string = "";
        foreach ($params as $key => $value){
            if (empty($value)) {
                unset($params[$key]);
            }

            $param_string .= rawurlencode($key) . '='. rawurlencode($value) . '&';
        }

        $param_string = rtrim($param_string, '&');
        $base_string .= rawurlencode($param_string);

        $this->base_string = $base_string;
        return $base_string;
    }

    /**
     * Generates a HMAC-SHA OAuth signature string.
     *
     * @param string $base_string The OAuth base string
     * @return string The signature.
     */
    private function hmacSignature(string $base_string)
    {
        $key = rawurlencode($this->config->getConsumerSecret())
            . '&' . rawurlencode($this->config->getTokenSecret());

        $hmac_method = OAuth1Config::HMAC_METHOD_MAP[$this->config->getOauthSignatureMethod()];
        $signature = base64_encode(hash_hmac($hmac_method, $base_string, $key, true));

        return $signature;
    }

    /**
     * Generates a RSA-SHA OAuth signature string.
     * 
     * @param string $base_string The OAuth base string
     * @return string The signature.
     */
    private function rsaSignature(string $base_string)
    {
        // TODO: Allow users to 
        $signature = '';
        $private_key = new RsaPrivateKey('', '');
        $rsa_method = OAuth1Config::RSA_METHOD_MAP[$this->config->getOauthSignatureMethod()];
        $success = openssl_sign($data, $signature, $private_key->getPrivateKey(), $rsa_method)

        if (!$success) {
            throw new OAuthException(openssl_error_string());
        }

        return $signature
    }

    /**
     * Work out which method of signing the user wants to use.
     * 
     * @param string $method The signature method.
     */
    private function determineSignatureMethodType($method)
    {
        if (in_array($method, OAuth1Config::HMAC_METHOD_MAP)) {
            return OAuth1Config::HMAC;  
        }

        if (in_array($method, OAuth1Config::RSA_METHOD_MAP)) {
            return OAuth1Config::RSA;
        }

        if ($method === OAuth1Config::PLAINTEXT) {
            OAuth1Config::PLAINTEXT;
        }

        return '';
    }

    /////////////////////////////////
    ////// Getters and Setters /////
    ///////////////////////////////

    /**
     * Get the value of config
     *
     * @return OAuth1Config
     */
    public function getConfig()
    {
        return $this->config;
    }

    /**
     * Set the value of config
     *
     * @param OAuth1Config $config
     */
    public function setConfig(OAuth1Config $config)
    {
        $this->config = $config;
    }

    /////////////////////////////////
    /////// Read-only Getters //////
    ///////////////////////////////

    /**
     * Get the value of $base_string.
     * Best used for debugging.
     *
     * @return string
     */
    public function getBaseString()
    {
        return $this->base_string;
    }

    /**
     * Get the value of $signature.
     * Best used for debugging.
     *
     * @return string
     */
    public function getSignature()
    {
        return $this->signature;
    }
}
