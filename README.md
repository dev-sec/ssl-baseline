ssl-baseline
===================

This Compliance Profile demonstrates the use of InSpec's [SSL resource](https://www.inspec.io/docs/reference/resources/ssl/) by enforcing strong TLS configuration.

The tests are based on
- [Mozillas TLS Guidelines](https://wiki.mozilla.org/Security/Server_Side_TLS)
- [OWASP TLS Cheat Sheet](https://www.owasp.org/index.php/Transport_Layer_Protection_Cheat_Sheet)
- [Cipherli.st](https://cipherli.st/)

## Standalone Usage

Requires [InSpec](https://github.com/chef/inspec) 1.21.0 or newer for execution:

```
$ git clone https://github.com/dev-sec/ssl-baseline
$ inspec exec ssl-baseline
```

You can also execute the profile directly from Github:

```
$ inspec exec https://github.com/dev-sec/ssl-baseline
```

## Covered Attacks / Weaknesses

- [Return Of Bleichenbacher's Oracle Threat (ROBOT)](https://robotattack.org/)

## Contributors + Kudos

* Dominik Richter [arlimus](https://github.com/arlimus)
* Christoph Hartmann [chris-rock](https://github.com/chris-rock)
* Alex Pop [alexpop](https://github.com/alexpop)
* Patrick Münch [atomic111](https://github.com/atomic111)
* Christoph Kappel [supergicko](https://github.com/supergicko)

## License and Author

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
