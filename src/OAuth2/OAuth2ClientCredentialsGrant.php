<?php

namespace OAuth\OAuth2;

class OAuth2PasswordCredentialsGrant extends OAuth2
{
    const GRANT_TYPE = 'client_credentials';

    /**
     * Create a x-www-form-urlencoded for an Client Credential grant access token request.
     *
     * `grant_type` is set implicitly.
     *
     * @param string $scope
     * @return string
     */
    public function getAccessTokenRequest($scope)
    {
        $params = [
            'grant_type' => self::GRANT_TYPE,
        ];

        if (!empty($scope)) {
            $params['scope'] = $scope;
        }

        return http_build_query($params, '', '&', PHP_QUERY_RFC3986);
    }
}
