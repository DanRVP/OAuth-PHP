<?php

namespace OAuth\OAuth2;

class OAuth2ImplicitGrant extends OAuth2
{
    const RESPONSE_TYPE = 'token';

    /**
     * Create query params for an Implicit grant authoriztion request.
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
    public function getAuthorizationRequest(array $params)
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
}
