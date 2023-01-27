# @libp2p/cms <!-- omit in toc -->

[![libp2p.io](https://img.shields.io/badge/project-libp2p-yellow.svg?style=flat-square)](http://libp2p.io/)
[![Discuss](https://img.shields.io/discourse/https/discuss.libp2p.io/posts.svg?style=flat-square)](https://discuss.libp2p.io)
[![codecov](https://img.shields.io/codecov/c/github/libp2p/js-libp2p-cms.svg?style=flat-square)](https://codecov.io/gh/libp2p/js-libp2p-cms)
[![CI](https://img.shields.io/github/actions/workflow/status/libp2p/js-libp2p-cms/js-test-and-release.yml?branch=main\&style=flat-square)](https://github.com/libp2p/js-libp2p-cms/actions/workflows/js-test-and-release.yml?query=branch%3Amain)

> Cryptographically protected messages using the libp2p keychain

## Table of contents <!-- omit in toc -->

- [Install](#install)
  - [Browser `<script>` tag](#browser-script-tag)
- [Features](#features)
  - [Cryptographic Message Syntax (CMS)](#cryptographic-message-syntax-cms)
- [API Docs](#api-docs)
- [License](#license)
- [Contribution](#contribution)

## Install

```console
$ npm i @libp2p/cms
```

### Browser `<script>` tag

Loading this module through a script tag will make it's exports available as `Libp2pCms` in the global namespace.

```html
<script src="https://unpkg.com/@libp2p/cms/dist/index.min.js"></script>
```

## Features

- Uses PKCS 7: CMS (aka RFC 5652) to provide cryptographically protected messages
- Delays reporting errors to slow down brute force attacks

### Cryptographic Message Syntax (CMS)

CMS, aka [PKCS #7](https://en.wikipedia.org/wiki/PKCS) and [RFC 5652](https://tools.ietf.org/html/rfc5652), describes an encapsulation syntax for data protection. It is used to digitally sign, digest, authenticate, or encrypt arbitrary message content. Basically, `cms.encrypt` creates a DER message that can be only be read by someone holding the private key.

## API Docs

- <https://libp2p.github.io/js-libp2p-cms>

## License

Licensed under either of

- Apache 2.0, ([LICENSE-APACHE](LICENSE-APACHE) / <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT ([LICENSE-MIT](LICENSE-MIT) / <http://opensource.org/licenses/MIT>)

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
