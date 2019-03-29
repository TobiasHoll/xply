<h1 align="center">xply</h1>

<h5 align=center>An exploit development framework for Python 3</h4>

<p align="center">
  <a href="#about">About</a> •
  <a href="#setup">Setup</a> •
  <a href="#contributing">Contributing</a> •
  <a href="#license">License</a>
</p>

## About

This is a ground-up rewrite of the great `pwnlib` for Python 2. There were a
number of attempts to port `pwnlib` to Python 3, but they all appear abandoned.
In addition, they still had a bunch of issues with the changes in Python 3,
especially when it comes to the handling of binary data.

`xply` does not have nearly the range of features that `pwnlib` has (although
more will be added over time), but was written from the ground up with Python 3
in mind.

## Setup

You can install `xply` using `pip`:

```bash
pip install xply
```

`xply` requires at least Python 3.7 (for `from __future__ import annotations`).

## Contributing

Contributions are always welcome! If you encounter a bug or have a feature request, please [open an issue](https://github.com/tobiasholl/xply/issues/new) on GitHub. Feel free to create a [pull request](https://help.github.com/articles/creating-a-pull-request/) for your improvements.

## License

xply is licensed under the MIT license, as found in the LICENSE file.

----

<sup>© 2019 Tobias Holl (@TobiasHoll)</sup>
