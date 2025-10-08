### 0.3.6 (2025-10-08)
Fix - verify aspath buffer size for incorrect sized ASn

### 0.3.5 (2025-10-03)
Fixed AS path - as_set & as_sequence

### 0.3.3 (2022-01-17)

#### Features
* log crate using
* unknown capability ignore

#### Fixes
* aggregatoras attribute adaptive for BMP

### 0.3.2 (2022-01-17)

#### Features
* BMP decode route monitoring with parameters from previously caught BGP OPEN messages
* Support for addpath detection for BMP route monitoring

### 0.3.1 (2022-01-16)

#### Fixes
* fixed panic on invalid ipv6 record length

### 0.3.0 (2022-10-08)

#### Features

* serde deserializaion support
* mdt safi (multicast distribution tree) added

#### Fixes

* clippy fixes

### 0.2.1 (2021-08-01)

#### Features

* multiple AddPath capabilities support

### 0.2.0 (2021-07-25)

#### Features

* AddPath support
* afi::BgpNet support for MAC prefixes
* extcommunity varieties extended

### 0.1.5 (2021-07-19)

#### Features

* examples added

#### Fixes

* many extra buffer checks

### 0.1.4 (2021-07-14)

#### Features

* EVPN display improved, MacAddress display improved. ([83ac56c]https://github.com/wladwm/zettabgp/commit/83ac56ce9af94d628877f48fc7b3f9be4cb05200))

### 0.1.3 (2021-07-13)

#### Fixes

* fixed EVPN encoding. ([cfc9bc1](https://github.com/wladwm/zettabgp/commit/cfc9bc1b47287cfe7e37d6fdbe9644d6cb3a69cc))

### 0.1.2 (2021-05-23)

#### Features

* **BgpError:** add a too_many_data() constructor to BgpError. ([9913afb](https://github.com/wladwm/zettabgp/commit/9913afb635c1120acdeb92ece1bcc4eba43edf3a))
* **BgpNet:** added utility struct BgpNet - like std::net::IpAddr but with prefix len. ([713563a](https://github.com/wladwm/zettabgp/commit/713563a5d5771fb53f1f4afeba88a6ebfa158e6f))
* **BgpExtCommunity:** added rt_ipn contructor for extended community route target IPv4:N. ([791af48](https://github.com/wladwm/zettabgp/commit/791af4804c0639bf5b5109a9591200983ce4cf0f))
* Fixed MP withdraws encoding. ([2db5497](https://github.com/wladwm/zettabgp/commit/2db54977439a3051d05f5c54f7db6fcb36ecf5b8))

#### Fixes

* **BgpASpath:** fixed encoding. ([f85c4b8](https://github.com/wladwm/zettabgp/commit/f85c4b86f67b2c8b8c5f0b3d441b15cb6122b705))
* Methods descriptions fixed on ipv4 and ipv6 nets ([4b10770](https://github.com/wladwm/zettabgp/commit/4b10770493cd08ac9751079e65de35e0f63a7e81))

### 0.1.1 (2021-05-04)

Fixed descriptions and readme

### 0.0.1 (2021-05-04)

First release


