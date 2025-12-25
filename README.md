**apass** is a passwords manager with attributes support.

### Documentation
See man page `apass(1)` for details.

### FAQ
**Q:** How it is different from [password-store](https://www.passwordstore.org)?\
**A:** The main difference is that `password-store` keeps list of your secret names open, `apass` keeps it encrypted. Another major feature of `apass` is a convenient attributes management. Arbitrary list of attributes can be associated with every secret.

### Examples
Create new secret for website.com and specify associated login and email attributes.
```shell
$ apass set -a login=username -a username@mail.box website.com
```
Print password associated with website.com.
```shell
$ apass website.com
```
Copy password for website.com to clipboard.
```shell
$ apass get -c website.com
```
Print all information associated with website.com.
```shell
$ apass get -A website.com
```

### Build and run
The app can be built using `cmake` command.
```shell
$ cmake .
$ cmake --build .
```
It is also possible to easily build a package for some operation systems. See `dist` folder in the current source distribution.
