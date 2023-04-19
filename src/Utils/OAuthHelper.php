<?php

namespace OAuth\Utils;

use DateTime;

/**
 * Helper methods
 * @author Dan Rogers
 */
class OAuthHelper
{
    /**
     * Get the current Unix timestamp.
     *
     * @return int
     */
    public static function getTimestamp()
    {
        $time = new DateTime();
        return $time->getTimestamp();
    }

    /**
     * Generate a random string of a specified length.
     *
     * @param int $length
     * @return string
     */
    public static function generateRandomString($length)
    {
        return substr(str_shuffle("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"), 0, $length);
    }
}
