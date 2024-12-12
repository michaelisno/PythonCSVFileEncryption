Info
----
Python csv file encryption/decryption program<br>
This program will decrypt an encrypted file into csv format on memory and then re-encrypt to disk.
This program encrypts using the file's meta data, so copies are not decryptable - only the original file.
The entire file is encrypted but each row is also encrypted with its own key and additional row-unique data.

Example
-------
The example file key is 'password'
Row '0's key is 'yes'
