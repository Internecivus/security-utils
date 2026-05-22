# Java Security Utilities

A small and simple Java utility library for hashing and validation of passwords using convention over configuration.


## Usage
#### 1. Configuration and initialization

Initialization is made using an instance of `CryptographyConfiguration` that holds all of the necessary parameters.


##### Example:
~~~~
final CryptographyConfiguration configuration = new CryptographyConfiguration(
        49_999, // number of iterations
        "PBKDF2WithHmacSHA512",  // hash algorithm
        ':', // hash part delimiter
        28, // key size in bytes
        128, // maximum password size
        false //uses pepper
);
final Cryptography cryptography = new Cryptography(configuration);
~~~~


#### 2. Hashing and validation

Hashing is done with `hashPassword()` and has four steps:
1. The provided password is hashed using password-based encryption (<i>PBE</i>) and a "randomly" generated salt.
2. A hash-message is constructed using the following format: `{ITERATIONS}{DELIMITER}{BASE64_ENCODED_SALT}{DELIMITER}{BASE64_ENCODED_HASHED_PASSWORD}` and encoded with Base64.
3. (optional) If a pepper is provided and the configuration supports using peppers, the hash-message is encrypted with symmetric AES encryption using a "randomly" generated IV and the pepper as the private key.
4. (optional) A cipher-message is constructed using the following format: `{INITIALIZATION_VECTOR}{ENCODED_HASH}` and encoded with Base64.

Validation of a password against a stored hash-message is done with `validatePassword()` and needs to use the same `CryptographyConfiguration` parameters as the hashing.


##### Example:
~~~~
// without pepper
final char[] hashedPassword = cryptographyWithoutPepper.hashPassword(validPassword);
final boolean isValid = cryptographyWithoutPepper.validatePassword(validPassword, hashedPassword);

// with pepper
final char[] hashedPassword = cryptographyWithPepper.hashPassword(validPassword, validPepper);
final boolean isValid = cryptographyWithPepper.validatePassword(validPassword, hashedPassword, validPepper);
~~~~


#### 3. Generator, CharUtils, SensitiveWork, DestroyableSecrets etc.
There are some other utility classes (i.e. secure random generation of char arrays, memory destruction of secret keys on throw or finish, etc.) that might prove useful for you but they are undocumented at this time. Feel free to check out the source.


## Notes
* The salt used is the same length as the key.
* Any exception thrown means something has gone terribly wrong and should be audited immediately.
* The resulting hash/cipher-message is a Base64 URL safe char array.
* Pepper size needs to be 256 bits (32 bytes).
* An effort has been made to clear the memory contents of sensitive data after a function is done using it. All such data is also destroyed in the event of any exception.
* You have to use the appropriate method with/without pepper depending on the used configuration.


## Recommendations
* Choose a reasonable maximum password length (i.e. 128-256 characters) to prevent Denial-of-Service attacks.
* Choose at least 10_000 iterations, and significantly more if performance is not an issue or security is paramount.
* Choose a key length of at least 168 bits (28 bytes).
* Use `fauxValidatePassword()` to prevent giving away information about credential existence.
