## Ransomeware

Bare bones of ransomeware i create for a client a while back. Yes i ended up not selling the code(I have a conscience).
This ransomeware uses the rjindael encryption to encrypt import files

## Disclaimer

This code is for educational purpose only. I am not responsible for whatever you do with the code. Be responsible and do not use this to harm anybody.

Although the ransomeware is relatively safe(as long as you do not forget the key and iv used to encrypt your files or you do not encrypt twice is a row), you should not run this on your personal computer.

## Compilation

#### Dependencies :

* nim compiler (version 1.0.0 and above)
* nimble package manager

For you local machine compile with

```bash

nimble make

```

## Excecution

Run

```bash

./ransomeware --help

```

To see the list of commands
