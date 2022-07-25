<?php

namespace OAuth;

use OAuth\Utils\OAuthException;

class OAuthConfig
{
    /**
     * @param array $oauth_params Associative array of parameters to be set.
     *              Acceptable params will be set while all others will be discarded.
     *              (Think of it as akin to Python's kwargs)
     * @throws OAuthException Setters can throw OAuth exceptions.
     */
    public function __construct(array $oauth_params = [])
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
     * Get the name of a setter for the property.
     *
     * Property naming convention is `snake_case`.
     * Method naming convention is `set + PascalisedPropertyName` which in
     * effect makes it `camelCase`.
     *
     * For example property `oauth_signature_method` becomes `setOauthSignatureMethod`.
     */
    private function getSetterName($property)
    {
        $parts = explode('_', $property);
        $pascalised = array_map('ucfirst', $parts);
        return 'set' . implode('', $pascalised);
    }
}
