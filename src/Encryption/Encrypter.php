<?php

namespace Baufragen\Encryption;

use Baufragen\Exception\DecryptionException;
use Baufragen\Exception\EncryptionException;

class Encrypter {

    protected $secret = null;
    protected $cipher = 'aes-256-cbc';

    /**
     *
     * @param string $secret  Your personal Baufragen.de API secret
     * @param string $cipher  The cipher to use for encryption. Currently only AES 256 CBC is supported.
     */
    public function __construct($secret, $cipher = 'aes-256-cbc') {
        $this->secret = $secret;
        $this->cipher = $cipher;
    }

    /**
     * This method takes a string and encrypts it using your API secret.
     * You get a base64 encoded string back that's safe to use in URLs and can be passed
     * to the Baufragen.de API.
     *
     * @param string $value The value you want to have encrypted
     * @return string The encrypted value
     * @throws EncryptionException
     */
    public function encryptString($value) {
        // generate an input vector depending on the used cipher
        $iv = random_bytes(openssl_cipher_iv_length($this->cipher));

        // encrypt the value with your secret and the generated input vector
        $value = \openssl_encrypt(
            $value, $this->cipher, $this->secret, 0, $iv
        );

        if ($value === false) {
            throw new EncryptionException("Value could not be encrypted");
        }

        // base64_encode the iv so the json_encode doesn't run into utf8 problems
        $iv = base64_encode($iv);

        // create json from iv and value so it can be decrypted again
        $json = json_encode(compact('iv', 'value'));

        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new EncryptionException('Could not encrypt the data.');
        }

        // base64_encode again so result can safely be transmitted in an URL
        return base64_encode($json);
    }

    /**
     * This method decrypts the given value and returns the original.
     * You can use it to decrypt values from the Baufragen.de API easily.
     *
     * @param string $value The value you got from our API and want to decrypt.
     * @return string The original decrypted value
     * @throws DecryptionException
     */
    public function decryptString($value) {
        // decode the value
        $payload = json_decode(base64_decode($value), true);

        if (!$this->validPayload($payload)) {
            throw new DecryptionException('Could not decrypt the data');
        }

        // decode the iv so we can use it during decryption
        $iv = base64_decode($payload['iv']);

        // decrypt the value
        $decrypted = \openssl_decrypt(
            $payload['value'], $this->cipher, $this->secret, 0, $iv
        );

        if ($decrypted === false) {
            throw new DecryptionException('Could not decrypt the data.');
        }

        return $decrypted;
    }

    /**
     * Checks after base64_decoding and json_decoding if the value is valid or if something
     * wrong was passed.
     *
     * @param array $payload    The array that needs to be checked for validity
     * @return bool             Returns true if the values are valid, otherwise false
     */
    protected function validPayload($payload) {
        return is_array($payload) && isset($payload['iv'], $payload['value']);
    }

}