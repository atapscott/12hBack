![alt text](https://docs.google.com/uc?id=140eH3ie99LowXHAoqruuD1c7JLaR8d5l "Logo Title Text 1")


# Back end for SN 12h/Marató

Simple lightweight backend to allow clients to push key/value pairs in a secure way.

## Open Endpoints

Open endpoints require no Authentication.

* Login: `POST /api/user/`

Create a new user. 
Expects an encoded JSON MIME type data field with a _username_ and _password_ field.
Password is stored encoded.

## Endpoints that require Authentication

Closed endpoints require a valid username/password to be included in the header of the
request.

### UserKeyValue related

Each endpoint manipulates or displays information related to the UserKeyValues. The user provided in the authentication
header is used to fetch the relevant data:

* Get Key Values: `GET /api/keyvalues`

Requires the usual authentication headers and provides a JSON object with the relevant key/value pairs.

* Get Key Value: `GET /api/keyvalue/<key_name>`

Requires the usual authentication headers and provides the value for the specified key name (if exists).

* Update Key Value: `GET /api/keyvalue/<key_name>`

Requires the usual authentication headers generates the relevant key/value pair. If either the key or the key/value
entities don'r exist they're generated.

* Purge data: `GET /api/purge`

Kills the whole database. Only available for privileged admin users. Rebuilds the base model right after.

