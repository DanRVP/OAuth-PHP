# OAuth-PHP
A PHP Library for OAuth 1 and OAuth 2 workflows.

### Installation
```
composer require dan-rogers/oauth-php
```

### Usage

####
OAuth 1 Example
- Use an array of options to create a config for your auth generation.
- Construct a new `OAuth1Config` object and use the array as the argument.
- Construct a new `OAuth1` object and use your `OAuth1Config` object as the argument.
- Call generateAuthorization(). 

So long as you have provided the correct information for the OAuth1 step you are on, it will generate a valid auth header. 

For more information on OAuth 1 usage see: 
- https://oauth.net/1/
- https://www.rfc-editor.org/rfc/rfc5849

```php
#!/usr/bin/php
<?php

use OAuth\OAuth1\OAuth1;
use OAuth\OAuth1\OAuth1Config;

require __DIR__ . '/vendor/autoload.php';

$config  = new OAuth1Config([
    'oauth_callback' => 'https://my_website/my_service/auth',
    'oauth_consumer_key' => 'CONSUMER_KEY',
    'consumer_secret' => 'CONSUMER_SECRET',
    'realm' => 'MY_REALM',
    'oauth_signature_method' => OAuth1Config::HMAC_SHA256,
]);

$oauth = new OAuth1($config);
$auth_header = $oauth->generateAuthorization('https://third_party/token_endpoint', 'POST');

// Example usage using PHP CURL

$ch = curl_init();
curl_setopt_array($ch, [
    CURLOPT_URL => 'https://third_party/token_endpoint',
    CURLOPT_CUSTOMREQUEST => 'POST',
    CURLOPT_HTTPHEADER => [
        'Authorization: ' . $auth_header,
        'Content-Length: 0',
    ],
]);

$response = curl_exec($ch);
```
