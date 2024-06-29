# SSH key

Generate a (RSA) SSH key pair to use with the honeypot server, and update private key path in the source code `honeypot.py`.

# Usage

```sh
python honeypot.py -p port
```
where the SSH server will bind to the specified port. An SSH client can be run using:-
```sh
ssh username@localhost -p port
```
where the username is one from `usernames.txt`.
