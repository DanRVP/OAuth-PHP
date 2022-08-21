<?php

namespace OAuth\OAuth2;

use OAuth\Utils\OAuthException;

/**
 * Contains helper methods for building OAuth 2.0 requests
 * @author Dan Rogers
 */
class OAuth2
{
    /**
     * @var string
     */
    protected $last_state;

    /**
     * @var string
     */
    protected $last_redirect;

    /**
     * Check that the state that has been returned is equal to the state sent.
     *
     * @param string $state
     * @return bool
     */
    public function verifyState($state)
    {
        return $state == $this->last_state;
    }

    /**
     * Get a constant from the current class.
     *
     * @param string $constant_name
     */
    protected function getConstant($constant_name)
    {
        $class_name = get_class($this);
        return constant("$class_name::$constant_name");
    }

    /**
     * Check that fields exist in an array and that they are no empty.
     * Throws an OAuthException with a list of invalid fields on failure.
     *
     * @param array $params
     * @throws OAuthException
     */
    protected function checkRequiredFields($params)
    {
        $invalid = [];
        foreach ($this->getConstant('REQUIRED_FIELDS') as $field) {
            if (empty($params[$field])) {
                $invalid[] = $field;
            }
        }

        if (!empty($invalid)) {
            $key_list = implode(', ', $invalid);
            throw new OAuthException("The following keys are required and cannot be empty: $key_list");
        }
    }
}
