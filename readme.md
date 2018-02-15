## About this SDK
This SDK is intended to ease communication and development with the API of www.baufragen.de. For problems and questions please contact us at support@baufragen.de

## Installation
To install this package just install it via composer.

```
composer require baufragen/sdk-php
```

After installing it in your project you can use the functionality described below by instantiating the classes in the Baufragen namespace.

## Encrypter
The Encrypter class helps you handle the nitty gritty details of Encryption using OpenSSL.
To use the Encrypter class simply create an object passing your Baufragen.de API Secret like this:

```
use Baufragen\Encryption\Encrypter;

$encrypter = new Encrypter(API_SECRET);
``` 

#### Encryption
Encrypting works simply by calling the encryptString method on the $encrypter object. You can then send the returned string to the Baufragen.de API.

```
$encrypted = $encrypter->encryptString('Hello World');
```

#### Decryption
Decrypting is as easy as encrypting. Simply call the decryptString method and pass it the encrypted value you got from our API and it will return the decrypted original.

```
$encryptedValue = '[ENCRYPTED]';
$decrypted = $encrypter->decryptString($encryptedValue);
```