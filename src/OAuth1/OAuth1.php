<?php

namespace OAuth\OAuth1;

use OAuth\Utils\OAuthHelper;
use OAuth\Utils\RsaPrivateKey;
use OAuth\Utils\OAuthException;

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
     * @param OAuthConfig $config
     */
    public function __construct($config)
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
    public function generateAuthorization($url, $method, array $extra_params = [])
    {
        $request_params = $this->config->getHeaderParams();

        // Determine which method we are signing with.
        $signature_method = $this->config->getOauthSignatureMethod();
        $signature_type = $this->determineSignatureMethodType($signature_method);

        if ($signature_type !== OAuth1Config::PLAINTEXT) {
            // These are not needed when using PLAINTEXT as the signature type.
            $request_params['oauth_timestamp'] = OAuthHelper::getTimestamp();
            $request_params['oauth_nonce'] = OAuthHelper::generateRandomString(20);
        }

        $request_params['oauth_signature'] = $this->buildOauthSignature(
            $signature_type,
            $url,
            $method,
            array_merge($request_params, $extra_params)
        );

        return $this->buildOauthHeader($request_params);
    }

    /**
     * Build a valid OAuth signature based on the signature type.
     *
     * @param string $signature_type The type of signature we use.
     * @param string $http_method HTTP method of the request.
     * @param string $url Url of the request.
     * @param array $params An array of parameters used to build the string.
     * @return string A signature.
     */
    private function buildOauthSignature(
        string $signature_type,
        string $url,
        string $method,
        array $params
    )
    {
        // Probably an invalid signature type.
        if (empty($signature_type)) {
            throw new OAuthException('Invalid signature type: ' . $signature_type);
        }

        $base_string = $this->buildBaseString($method, $url, $params);
        $signature = '';

        if ($signature_type === OAuth1Config::HMAC) {
            $signature = $this->hmacSignature($base_string);
        } else if ($signature_type === OAuth1Config::RSA) {
            $signature = $this->rsaSignature($base_string);
        } else if ($signature_type === OAuth1Config::PLAINTEXT) {
            $signature = $this->generateSecretPair();
        }

        $this->signature = $signature;
        return $signature;
    }

    /**
     * Builds the OAuth 1.0 Authorization header.
     *
     * @param array $params Array of parameters used to create signature.
     * @return string The OAuth header
     */
    private function buildOauthHeader($params)
    {
        $header = 'OAuth ';

        $realm = $this->config->getRealm();
        if (!empty($realm)) {
            $header .= 'realm="' . $this->config->getRealm() . '", ';
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
    private function buildBaseString($http_method, $url, array $params)
    {
        //http method must be upper case
        $base_string = strtoupper($http_method) . '&';
        $base_string .= rawurlencode($url) . '&';

        //all parameters must be alphabetically sorted
        ksort($params);

        $param_string = "";
        foreach ($params as $key => $value) {
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
    private function hmacSignature($base_string)
    {
        $key = $this->generateSecretPair();
        $hmac_method = OAuth1Config::HMAC_METHOD_MAP[$this->config->getOauthSignatureMethod()];
        return base64_encode(hash_hmac($hmac_method, $base_string, $key, true));
    }

    /**
     * Generates a RSA-SHA OAuth signature string.
     *
     * @param string $base_string The OAuth base string
     * @return string The signature.
     */
    private function rsaSignature($base_string)
    {
        $signature = '';
        $private_key = new RsaPrivateKey(
            $this->config->getRsaPrivateKey(),
            $this->config->getRsaPassphrase()
        );

        $rsa_method = OAuth1Config::RSA_METHOD_MAP[$this->config->getOauthSignatureMethod()];
        $success = openssl_sign(
            $base_string,
            $signature,
            $private_key->getPrivateKey(),
            $rsa_method
        );

        if (!$success) {
            throw new OAuthException(openssl_error_string());
        }

        return $signature;
    }

    /**
     * Work out which method of signing the user wants to use.
     *
     * @param string $method The signature method.
     * @return string
     */
    private function determineSignatureMethodType($method)
    {
        if (in_array($method, array_keys(OAuth1Config::HMAC_METHOD_MAP))) {
            return OAuth1Config::HMAC;
        }

        if (in_array($method, array_keys(OAuth1Config::RSA_METHOD_MAP))) {
            return OAuth1Config::RSA;
        }

        if ($method === OAuth1Config::PLAINTEXT) {
            OAuth1Config::PLAINTEXT;
        }

        return '';
    }

    /**
     * Get the rawurlendcode, concatenated consumer and token
     * secret for HMAC and PLAINTEXT signature types.
     *
     * @return string
     */
    private function generateSecretPair()
    {
        return rawurlencode($this->config->getConsumerSecret())
            . '&' . rawurlencode($this->config->getTokenSecret());
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
        if (!($config instanceof OAuth1Config)) {
            throw new OAuthException('Config type must be of OAuth1Config.');
        }

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
