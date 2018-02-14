<?php

namespace Baufragen\Encryption;

use Baufragen\Exception\DecryptionException;
use Baufragen\Exception\EncryptionException;

class Encrypter {

    protected $secret = null;
    protected $cipher = 'aes-256-cbc';

    public function __construct($secret, $cipher = 'aes-256-cbc') {
        $this->secret = $secret;
        $this->cipher = $cipher;
    }

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

    protected function validPayload($payload) {
        return is_array($payload) && isset($payload['iv'], $payload['value']);
    }

}