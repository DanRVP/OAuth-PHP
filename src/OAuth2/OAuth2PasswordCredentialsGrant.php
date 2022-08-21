<?php

namespace OAuth\OAuth2;

class OAuth2PasswordCredentialsGrant extends OAuth2
{
    const GRANT_TYPE = 'password';
    const REQUIRED_FIELDS = [
        'username',
        'password',
        'grant_type',
    ];

    /**
     * Create a x-www-form-urlencoded for a Resource Owner Password Credentials grant access token request.
     *
     * `grant_type` is set implicitly.
     *
     * @param array $params
     * @return string
     *
     * ```
     * $params = [
     *    'username' => 'username'
     *    'password' => 'password',
     *    'scope' => 'scope',
     * ];
     * ```
     */
    public function getAccessTokenRequest(array $params)
    {
        $this->checkRequiredFields($params);

        $params['grant_type'] = self::GRANT_TYPE;
        return http_build_query($params, '', '&', PHP_QUERY_RFC3986);
    }
}
