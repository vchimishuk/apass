**apass** is a passwords manager with attributes support.

### Documentation
See man page `apass(1)` for details.

### FAQ
**Q:** How it is different from [password-store](https://www.passwordstore.org)?\
**A:** The main difference is that `password-store` keeps list of your secret names open, `apass` keeps it encrypted. Another major feature of `pass` is a convenient attributes management. Arbitrary list of attributes can be associated with every secret.

### Examples
Create new secret for websitecom and specify associated login and email attributes.
```shell
$ apass set -a login=username -a username@mail.box websitecom
```
Print password associated with websitecom.
```shell
$ apass websitecom
```
Copy password for websitecom to clipboard.
```shell
$ apass get -c websitecom
```
Print all information associated with websitecom.
```shell
$ apass get -A websitecom
```

### Build and run
The app can be built using `cmake` command.
```shell
$ cmake .
$ cmake --build .
```
It is also possible to easily build a package for some operation systems. See `dist` folder in the current source distribution.
