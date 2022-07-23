<?php 

namespace OAuth\Utils;

/**
 * Wrapper for getting a OpenSSLAsymmetricKey.
 * @author Dan Rogers
 */
class RsaPrivateKey
{
    /**
     * @var string
     */
    protected $key;
    
    /**
     * @var string
     */
    protected $passphrase;

    public function __construct(string $key, string $passphrase = null)
    {
        $this->setKey($key);
        $this->setPassphrase($passphrase);
    }

    /**
     * Get a OpenSSLAsymmetricKey based on the current key and passphrase.
     * 
     * @return OpenSSLAsymmetricKey
     */
    public function getPrivateKey()
    {
        return openssl_get_privatekey(
            $this->getKey(),
            $this->getPassphrase()
        );
    }

    /**
     * Get the value of $key.
     */
    public function getKey()
    {
        return $this->key;
    }

    /**
     * Set the value of $key.
     */
    public function setKey(string $key)
    {
        $this->key = $key;
    }

    /**
     * Get the value of $passphrase.
     */
    public function getPassphrase()
    {
        return $this->passphrase;
    }

    /**
     * Set the value of $passphrase.
     */
    public function setPassphrase(string $passphrase)
    {
        $this->passphrase = $passphrase;
    }
}
