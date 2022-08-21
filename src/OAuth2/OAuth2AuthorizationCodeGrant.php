<?php

namespace OAuth\OAuth2;

class OAuth2AuthorizationCodeGrant extends OAuth2
{
    const RESPONSE_TYPE = 'code';
    const GRANT_TYPE = 'authorization_code';
    const REQUIRED_FIELDS = [
        'code',
        'client_id',
    ];


    /**
     * Create query params for an Authorization Code grant authoriztion request.
     *
     * `response_type` is set implicitly.
     *
     * @param array $params
     * @return string
     *
     * ```
     * $params = [
     *      'client_id' => 'abc123',
     *      'redirect_uri' => 'https://test.com/auth',
     *      'scope' => 'scope',
     *      'state' => 'state',
     * ];
     * ```
     */
    public function getAuthorizationRequest($params)
    {
        if (array_key_exists('state', $params)) {
            $this->last_state = $params['state'];
        }

        if (array_key_exists('redirect_uri', $params)) {
            $this->last_redirect = $params['redirect_uri'];
        }

        $params['response_type'] = self::RESPONSE_TYPE;
        return '?' . http_build_query($params, '', '&', PHP_QUERY_RFC3986);
    }

    /**
     * Create a x-www-form-urlencoded for an Authorization Code grant access token request.
     *
     * `grant_type` is set implicitly.
     *
     * This method implicitly uses the redirect uri you used in the getAuthorizationRequest()
     * method if it was run, but this can be overriden by passing a value in the
     * params array with a key of `redirect_uri`.
     *
     *
     * @param array $params
     * @return string
     *
     * ```
     * $params = [
     *    'code' => 'xyz567'
     *    'client_id' => 'abc123',
     *    'redirect_uri' => 'https://test.com/auth',
     * ];
     * ```
     */
    public function getAccessTokenRequest(array $params)
    {

        if (!array_key_exists('redirect_uri', $params) && !empty($this->last_redirect)) {
            $params['redirect_uri'] = $this->last_redirect;
        }

        $this->checkRequiredFields($params);

        $params['grant_type'] = self::GRANT_TYPE;
        return http_build_query($params, '', '&', PHP_QUERY_RFC3986);
    }
}
