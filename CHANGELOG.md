# Changelog

## [0.11.2](https://github.com/takehaya/xdperf/compare/v0.11.1...v0.11.2) (2026-04-11)


### 🐛 Bug Fixes

* address PR review — propagate bpf_loop callback error and simplify nil guards ([e3c4589](https://github.com/takehaya/xdperf/commit/e3c4589a3aa77b2ef151a09aa09aba425e47a2bc))
* use bpf_loop for incremental checksum diff to avoid verifier limit ([44eff76](https://github.com/takehaya/xdperf/commit/44eff7682a02fc45a578353bfd8393cba23b44ab))
* verfier BPF program is too large error ([39c8cd1](https://github.com/takehaya/xdperf/commit/39c8cd15d8286c395ca0ffe9eeb6efaf1161f93a))


### ⚡ Performance Improvements

* add wazero CompilationCache for faster WASM plugin startup ([e0fb3c5](https://github.com/takehaya/xdperf/commit/e0fb3c572bd1fb1f947fa32177a82fb0611860c8))
* add wazero CompilationCache for faster WASM plugin startup ([7e6a1b4](https://github.com/takehaya/xdperf/commit/7e6a1b4b84d39b1f1a341216f4db0c91de3cf312))

## [0.11.1](https://github.com/takehaya/xdperf/compare/v0.11.0...v0.11.1) (2026-03-24)


### ⚡ Performance Improvements

* optimize BPF program for verifier compatibility and reduced states ([b6e5081](https://github.com/takehaya/xdperf/commit/b6e50817cb522d3ad348e0c6a30e0a50bb20e994))


### 📝 Documentation

* add multi-kernel test instructions to README ([a6dd94e](https://github.com/takehaya/xdperf/commit/a6dd94ecc8337feb402f1ed292300bbcc475c13e))


### 🔧 Miscellaneous Chores

* modify text ([eba1731](https://github.com/takehaya/xdperf/commit/eba17319f0cf72ba788d5f1043ae94289fbc61df))
* modify text ([5a1621d](https://github.com/takehaya/xdperf/commit/5a1621de5b8f314a8628e7fcbedbba6394367b2e))
* tuning xdperf docs and verifier log ([c2486d9](https://github.com/takehaya/xdperf/commit/c2486d96c7107f47295c30b0ce885e813b670f16))
* tuning xdperf docs and verifier log ([4a28a78](https://github.com/takehaya/xdperf/commit/4a28a78542e12faaec36bffccfad3345b6e89738))


### ♻️ Code Refactoring

* simplify verifier log to debug-only mode to prevent OOM ([27b7321](https://github.com/takehaya/xdperf/commit/27b7321ee2a7edb239152dc4a9d64834c468f7a5))

## [0.11.0](https://github.com/takehaya/xdperf/compare/v0.10.0...v0.11.0) (2026-02-27)


### 🎉 Features

* add checksum and diff entry structures ([9204839](https://github.com/takehaya/xdperf/commit/9204839b3ed5d823664e3214d7753c8256bdb242))
* add checksum and diff entry structures ([3f761c9](https://github.com/takehaya/xdperf/commit/3f761c98ada47f78d6ebe263504fe31a44c636f1))
* add diff calc logic to bpf ([de5bb2d](https://github.com/takehaya/xdperf/commit/de5bb2d36a7478d36d2db9853f660d7d73510af0))
* add helper functions for diff-based packet generation ([4611c45](https://github.com/takehaya/xdperf/commit/4611c45cdf22a6258a619b98e7d7de3f7647f121))
* add test e2e variety plugin ([2eb2f9b](https://github.com/takehaya/xdperf/commit/2eb2f9b69cd9791a9131ddfb8b8bcca69c2cbee6))
* add test e2e variety plugin ([61e3f5e](https://github.com/takehaya/xdperf/commit/61e3f5e23376fb482e879aec6d1a434778e129e1))
* diff based packet generation ([9cc5906](https://github.com/takehaya/xdperf/commit/9cc59062d2e4399378e3747f705f6186ad1e4cfa))
* implement geneator ([42e1deb](https://github.com/takehaya/xdperf/commit/42e1deb60e19af8f86545a4dc88ce22aab9c763d))
* implement geneator ([64670c4](https://github.com/takehaya/xdperf/commit/64670c46fa34fa72ba1d19919d24763957d2b89d))


### 🐛 Bug Fixes

* add boundary check ([caba0e4](https://github.com/takehaya/xdperf/commit/caba0e44b3fe4be612dd24868ce0529b3bf96511))
* add boundary checks for target length in update_packet_lengths function ([99ba6dc](https://github.com/takehaya/xdperf/commit/99ba6dc7568059f9de587df73a330419cd0e9384))
* add ICMPv4 checksum calculation support ([048c512](https://github.com/takehaya/xdperf/commit/048c512f0c40de94c2313f59c83e672852d74978))
* add packets incluiding payload to tcp example ([1276404](https://github.com/takehaya/xdperf/commit/12764046a2fbf8ed2ca399aca53e06fccfaf0be4))
* add start and end validation ([723d0af](https://github.com/takehaya/xdperf/commit/723d0afd521e3957008e87fe9f8ab23ebf15d28e))
* add TODO comments for unsupported IPv6 extension headers in checksum calculations ([ff3ad93](https://github.com/takehaya/xdperf/commit/ff3ad930b804d07269a567b75ec59f31e01f8f35))
* adjust SRH header size and loading logic in ipv6_find_transport ([751b0cf](https://github.com/takehaya/xdperf/commit/751b0cfacbfd6eae4209822970ffe7c573b5909d))
* build error ([b47477e](https://github.com/takehaya/xdperf/commit/b47477eb40c621dfd062c9b4dfc57c0d82055355))
* calc checksum algorithm ([e5ccdee](https://github.com/takehaya/xdperf/commit/e5ccdee31765321d93358b212b5236b2c835cc05))
* checksum calculation for diff sizes 4, 6, and 8 with offset handling ([c2b0428](https://github.com/takehaya/xdperf/commit/c2b04284729e2711900ec380c095bbe3d47586e9))
* delete pragma unroll ([12a4397](https://github.com/takehaya/xdperf/commit/12a4397a61cf6141c248687662f4daba7d9d2122))
* diff based packet generation bpf encap ([d7e29e0](https://github.com/takehaya/xdperf/commit/d7e29e03cdf24b5a306537fb8902b57cb815315b))
* icmpv4 checksum ([2dd36ac](https://github.com/takehaya/xdperf/commit/2dd36ac85ae9707be12ff52c07642be3eb88fca4))
* introduce isAllowedByteSize function ([00411c9](https://github.com/takehaya/xdperf/commit/00411c937b5ed09bab20e47c7c0014c875595beb))
* make checksum metadata to PERCPU array ([c5854e9](https://github.com/takehaya/xdperf/commit/c5854e9b4e522c5abaa8d5d5654ff92a3224b063))
* make initChecksumMetaMaps PER CPU ARRAY ([2b5d348](https://github.com/takehaya/xdperf/commit/2b5d348076cddbafb8c2c4a4f841c8e910a8226e))
* modify apply_diff function to handle sizes 6 and 8 with proper error handling ([afca2cc](https://github.com/takehaya/xdperf/commit/afca2ccd69d2544534f92498223051426ab23557))
* modify to define magic numbers as const ([b5fd8c0](https://github.com/takehaya/xdperf/commit/b5fd8c022aa72c336412800f13b26f08fe7426c7))
* refactor apply_diff function to validate diff sizes to reduce redundancy ([e858836](https://github.com/takehaya/xdperf/commit/e858836882faca535ad96e740d73439cf836bdc6))
* refactor recalc_checksum and diff_affects_checksum functions to check whether it is ipv4 header or not ([d1ead1a](https://github.com/takehaya/xdperf/commit/d1ead1ad23cb3572749dbd58655bb7eab9ddb782))
* remove unreachable code ([187ef7f](https://github.com/takehaya/xdperf/commit/187ef7f339010e98639d0a730bb727a36391f9e4))
* rename MAX_TEMPLATE_SIZE to MAX_PACKET_SIZE ([5d419fa](https://github.com/takehaya/xdperf/commit/5d419fa9c58639472480d8dd2e2e66e507609bf9))
* revert dstMAC update ([84bc27a](https://github.com/takehaya/xdperf/commit/84bc27aff169e64fc2549c4e34bb040079835b91))
* srv6 checksum handling ([809bc93](https://github.com/takehaya/xdperf/commit/809bc93124aaa74c66a363a47432181964efe2c2))
* update Go version to 1.26.0 ([dd77162](https://github.com/takehaya/xdperf/commit/dd7716201f603a7624ebf54018c46e49b7f1a497))
* update goreleaser to release new plugins ([69d982f](https://github.com/takehaya/xdperf/commit/69d982faaa4ad4e0cd15b0bfa4202b544cbf1503))
* update isAllowedByteSize function to use slices.Contains for validation ([60b1c26](https://github.com/takehaya/xdperf/commit/60b1c2690786cfb981d051ca50b3b333f58404ac))
* update other plugins ([d86ce11](https://github.com/takehaya/xdperf/commit/d86ce11c47165df1944f33988a19de93826c68bf))
* update other plugins ([bafd3fa](https://github.com/takehaya/xdperf/commit/bafd3fa03c2f87d749005dd04948caba77b3218c))
* update return values in apply_diff and recalc_checksum functions for better error handling ([b3c11ed](https://github.com/takehaya/xdperf/commit/b3c11edf13bd0ed4baa9757a6b55351bc5b29f13))
* update TODO for IPv4 header checksum for IP options ([51adfdd](https://github.com/takehaya/xdperf/commit/51adfdd37a7ea859c923af32578379ababff107c))
* update unnatural packet generation ([d71a58e](https://github.com/takehaya/xdperf/commit/d71a58ed513ad533b76260be78c4ad3a63818c3f))
* use bpf_loop in ICMPv4 checksum calculation ([bd66b10](https://github.com/takehaya/xdperf/commit/bd66b1069d8566060da393f26ad20ff09be562ea))
* use go releaaser v2.13.3 ([e584d2f](https://github.com/takehaya/xdperf/commit/e584d2fd4b9c4d64388d2dfc555fd07e8a7be98b))
* use IPv4ToUint64 for readability ([4d7826a](https://github.com/takehaya/xdperf/commit/4d7826aa58687774d80351078f32ce2fa321df21))
* use istrings.EqualFold for "all" param ([c2eb750](https://github.com/takehaya/xdperf/commit/c2eb7505dcd9f57c6c7fa0e8b286070fe8854923))
* use lower in GetProtocolsToInclude ([d067428](https://github.com/takehaya/xdperf/commit/d067428063ac77517d7e592e2350c44aab71d86a))
* validate l3_offset after VLAN parsing in update_packet_lengths function ([70546a2](https://github.com/takehaya/xdperf/commit/70546a2004e03d86c87103bf5f219da051bd7cc9))


### 🔧 Miscellaneous Chores

* add blank line ([d51ff3a](https://github.com/takehaya/xdperf/commit/d51ff3ac288fc52c1f0bd784800a05121b4b5857))
* add comments for supported checksum types ([80cbef2](https://github.com/takehaya/xdperf/commit/80cbef213f10effc32430b09060f70c127e8bbe4))
* add README for test_e2e_variety.go ([72cb33e](https://github.com/takehaya/xdperf/commit/72cb33e2e6ba4f630f3919b5a78055b5bbef621e))
* add unit tests ([937f7ce](https://github.com/takehaya/xdperf/commit/937f7ceb0d3833827efac6354ddbf020078a4374))
* fix format ([266c665](https://github.com/takehaya/xdperf/commit/266c665c9b83f88710efebabe9bd96bb46a37d79))
* fix format ([f25b014](https://github.com/takehaya/xdperf/commit/f25b01434fccd2770492530dcc430bfd84ae9eec))
* fix logging format in main ([f81e9f2](https://github.com/takehaya/xdperf/commit/f81e9f2cf31592e925781c082247e2f523a6584c))
* modify not to use magic numbers ([364bdee](https://github.com/takehaya/xdperf/commit/364bdee2f3845ee4971127f271948cbd44ca9189))
* remove mpls ([8146cb3](https://github.com/takehaya/xdperf/commit/8146cb349f34e5fadd5bdfe02d794c1b41f1efdb))
* remove obvious comments ([d8c2192](https://github.com/takehaya/xdperf/commit/d8c2192dd98fc4fb5ece3db7aebc83e0873084f2))
* remove simple srv6 ([84993a0](https://github.com/takehaya/xdperf/commit/84993a09fa3a63632d60d3e178779759bcb6307d))
* update comments ([0eef67e](https://github.com/takehaya/xdperf/commit/0eef67e8ee1fa93183af5b36bc290182e8b3e716))
* update go to 1.25.5 ([3e0d85f](https://github.com/takehaya/xdperf/commit/3e0d85fefcc77622a8d827147dc0e1e88c090e3a))
* update incorrect comments ([0820d22](https://github.com/takehaya/xdperf/commit/0820d22942225ba9bf4e86d52efcec7498190f50))
* use fixed seed for generator_test.go ([7dabde7](https://github.com/takehaya/xdperf/commit/7dabde7fe4769f2a52eaafe736092f0ddd9f6932))


### ♻️ Code Refactoring

* load consts dynamically ([9852446](https://github.com/takehaya/xdperf/commit/98524469db3ddc76e8540306d007a6d24ccedd84))
* replace full packet copy with base + diff approach ([0c8c55a](https://github.com/takehaya/xdperf/commit/0c8c55a67aac368ff32f15f3e73b9843d63bc2c1))
* split vpn.go to 2 files ([f3ea1d2](https://github.com/takehaya/xdperf/commit/f3ea1d20baeda5b4dd6c144626787b378eda73fe))
* use bool instead of macro ([a249a30](https://github.com/takehaya/xdperf/commit/a249a30776321ff7896bb5a0cf84eef4a302dc6d))
* use builtin memcpy for simplification ([85ef8a1](https://github.com/takehaya/xdperf/commit/85ef8a1c9ac9e11be716fa32c7f5b8e0da16f554))
* use calc_ipv4_header_csum ([ec0348b](https://github.com/takehaya/xdperf/commit/ec0348bf7153372dbf328bdef6a6f372800970a5))
* use table based implementation ([4b4a7fe](https://github.com/takehaya/xdperf/commit/4b4a7fe9c9ecc4221a357b26ac4ba54de8a7e00b))
* xdperf packet generation and XDP program ([d079630](https://github.com/takehaya/xdperf/commit/d07963087f139909cc32f843c84a11e53a786cba))

## [0.10.0](https://github.com/takehaya/xdperf/compare/v0.9.0...v0.10.0) (2025-12-18)


### 🎉 Features

* add imix pattern plugin ([736168a](https://github.com/takehaya/xdperf/commit/736168adff96b6c6d225e6d14753369a6fddac92))


### 📝 Documentation

* inspired by ref ([24d313b](https://github.com/takehaya/xdperf/commit/24d313b8178a5925585d8396c81bf954cc3d1bfe))
* inspired by ref ([33c0ca4](https://github.com/takehaya/xdperf/commit/33c0ca493e4083e91d1556c6b06f6a6c5b25baea))


### 🔧 Miscellaneous Chores

* remove imix case ([ef3a1d9](https://github.com/takehaya/xdperf/commit/ef3a1d98e3433b09a802a41f8f42de02865c6d02))

## [0.9.0](https://github.com/takehaya/xdperf/compare/v0.8.0...v0.9.0) (2025-12-06)


### 🎉 Features

* skip arp lookup and dstmac intent ([7196f55](https://github.com/takehaya/xdperf/commit/7196f554409f720906c7ee0bba2bf01e4ac19a1e))
* skip arp lookup and dstmac intent ([6d89fbb](https://github.com/takehaya/xdperf/commit/6d89fbbf1a9b898ba9554549c4e13c074d30bafd))

## [0.8.0](https://github.com/takehaya/xdperf/compare/v0.7.1...v0.8.0) (2025-12-03)


### 🎉 Features

* add batch size params ([b472015](https://github.com/takehaya/xdperf/commit/b472015060d5e58c1caa3feee8f82943da52a423))
* add blast mode and map size compaction ([3a7b336](https://github.com/takehaya/xdperf/commit/3a7b33622dfb4c1f1a9edeca0c732ee6c3ffd662))
* add enable xdpcap ([7e4254f](https://github.com/takehaya/xdperf/commit/7e4254f4d6d34fedf7301ae7d54f1dfb86e73b8f))
* add memcpy optimize ([ed14bb7](https://github.com/takehaya/xdperf/commit/ed14bb738a05734d5c72bb67ed631fd7d55d3a8d))
* add support probe ([a043580](https://github.com/takehaya/xdperf/commit/a0435805039a872a324b14adece8edd74a392fc6))
* add xdperf.pdf ([1451c94](https://github.com/takehaya/xdperf/commit/1451c940b3b55890b743915a9c0a89817815d06b))
* blast mode and perf tuning ([068ec99](https://github.com/takehaya/xdperf/commit/068ec99459609b915348ec4da1381f8e02f30629))


### 📝 Documentation

* add perf report ([12ec4ce](https://github.com/takehaya/xdperf/commit/12ec4cebe48f43a27fec9da38aade41f085f1c94))
* add xdperf logo ([3e47b70](https://github.com/takehaya/xdperf/commit/3e47b70c7923a953efec62f4bb5cb925cb41e15d))
* add xdperf logo ([62595c8](https://github.com/takehaya/xdperf/commit/62595c8ba4c6f9ba392aba5cfbb90235e754c31d))
* modify readme ([9fdf8c4](https://github.com/takehaya/xdperf/commit/9fdf8c4a4acce63c6b219768266464be9452f5b9))
* modify readme ([4573d19](https://github.com/takehaya/xdperf/commit/4573d19f8de4e009f00159ac83807fe838c49260))
* modify readme ([0346a46](https://github.com/takehaya/xdperf/commit/0346a461ebf5a43abe4e8ef10a6b9aef336866d0))
* modify readme ([3f5fb5b](https://github.com/takehaya/xdperf/commit/3f5fb5b799fb267c10fdea26a35cb4ec7de3a0f1))
* modify readme ([7904efb](https://github.com/takehaya/xdperf/commit/7904efbe0b19b5d2c45c369e7af9a0513de5ce8a))
* modify readme ([c929ca9](https://github.com/takehaya/xdperf/commit/c929ca9df6681ca90979c76b8a0897fda14eb261))
* modify readme ([fefb643](https://github.com/takehaya/xdperf/commit/fefb643cfd9b909c8e641146d4c898611aa3505a))
* modify readme ([ccf8353](https://github.com/takehaya/xdperf/commit/ccf8353d552f3652fdb19e7c96c6e96d001d1263))
* remove noise docs ([dec14df](https://github.com/takehaya/xdperf/commit/dec14dfe217ad55df1f759008ad3aebb663b14f5))
* remove noise docs ([94d5b14](https://github.com/takehaya/xdperf/commit/94d5b145f413b7f59757ddd1fca77aa5d56d3f12))
* update docs ([5ac7bdf](https://github.com/takehaya/xdperf/commit/5ac7bdf8c8ff20f911aaf00dd30212dc4547e3c8))
* update tips perf ([1658b5a](https://github.com/takehaya/xdperf/commit/1658b5a805c5a5c70c968258379f93c9b8ddd7bb))
* update tips perf ([4584cdb](https://github.com/takehaya/xdperf/commit/4584cdbd35e77502a0036f6fc64246a88d2e42d8))


### 🔧 Miscellaneous Chores

* add test tips ([1fa41d4](https://github.com/takehaya/xdperf/commit/1fa41d4556f793b5c7b6a41a7cb6037b9304cef3))
* update go version ([3017202](https://github.com/takehaya/xdperf/commit/30172022eb8d0171b6ab8d98077794386a9ceb7f))


### ♻️ Code Refactoring

* rename to infinite ([1964f49](https://github.com/takehaya/xdperf/commit/1964f490b1a22cf08a8802b71f6d7db1f95befa7))

## [0.7.1](https://github.com/takehaya/xdperf/compare/v0.7.0...v0.7.1) (2025-11-30)


### 🐛 Bug Fixes

* argument validation for receiver mode ([08187b6](https://github.com/takehaya/xdperf/commit/08187b608b194e45f85bd322d381bab160fa5e24))
* argument validation for receiver mode ([e36afba](https://github.com/takehaya/xdperf/commit/e36afbaaf7400a42cf5d9a2f8f6b4f02e7f7ed0f))

## [0.7.0](https://github.com/takehaya/xdperf/compare/v0.6.0...v0.7.0) (2025-11-30)


### 🎉 Features

* add option to show NIC-level statistics ([adbd5f7](https://github.com/takehaya/xdperf/commit/adbd5f77ac9f6a63b7e0f2bf573e72120ba6e22e))
* add pps param ([3feb04e](https://github.com/takehaya/xdperf/commit/3feb04e3328579a2875e380dc3fdabf91e7d2267))
* fix count and pps parsing and validation ([5f274d4](https://github.com/takehaya/xdperf/commit/5f274d48a0657a196534ae79a50e4b1a44b0454d))
* specify pps ([5088e16](https://github.com/takehaya/xdperf/commit/5088e1653f5361d26e464f4a177e7ebf93a957f0))


### 🐛 Bug Fixes

* remove redundant args ([6a8ce43](https://github.com/takehaya/xdperf/commit/6a8ce4353999a879a63706ba876735b3c19a9670))
* use pprintf in stats.go ([66390cd](https://github.com/takehaya/xdperf/commit/66390cd8036ffd6b502c5054149db7de4a470b39))


### 🔧 Miscellaneous Chores

* delete unneccesary default value ([849de3c](https://github.com/takehaya/xdperf/commit/849de3c91797771736e4e57fcd621094523fdea2))
* fix inproper error handling ([de3a19d](https://github.com/takehaya/xdperf/commit/de3a19dc1e99cb55b9a78bea76ffee6dc826355f))
* update readme ([0cd347b](https://github.com/takehaya/xdperf/commit/0cd347b47a42facbd6d9cfa02950d482df9fb425))
* update README ([1af1994](https://github.com/takehaya/xdperf/commit/1af19940f81819e4738209b77763c3be92e984cf))

## [0.6.0](https://github.com/takehaya/xdperf/compare/v0.5.2...v0.6.0) (2025-11-30)


### 🎉 Features

* add send/recv counter mode ([cef982a](https://github.com/takehaya/xdperf/commit/cef982adb67b161387d0ee88d069a2f3140e9abf))


### 🐛 Bug Fixes

* add xdp_utils ([24b047d](https://github.com/takehaya/xdperf/commit/24b047d16a08e1616b1241860da19cfb29323e70))
* add xdp_utils ([61f1c6c](https://github.com/takehaya/xdperf/commit/61f1c6c0151dfd16eef5d90f340e38750ab595ee))


### 🔧 Miscellaneous Chores

* add server mode ([798d750](https://github.com/takehaya/xdperf/commit/798d7503548d8990fe3823132300d54599724571))
* add server mode ([b13b011](https://github.com/takehaya/xdperf/commit/b13b01115e585b5f59894f26ca6b2f16ccdb2c4e))
* modify install script ([0ed91ed](https://github.com/takehaya/xdperf/commit/0ed91ed5de6911d74306ad4ad8a0cd07e1d39c73))
* modify install script ([253e8a8](https://github.com/takehaya/xdperf/commit/253e8a89613c1e5cad30e57f3f8e214432102c7e))
* when run server mode, wasm plugin is ignore ([343fe57](https://github.com/takehaya/xdperf/commit/343fe57460638ece5095dd0217a6d7b23ed977d3))

## [0.5.2](https://github.com/takehaya/xdperf/compare/v0.5.1...v0.5.2) (2025-11-30)


### 🐛 Bug Fixes

* pkt entry size and lookup mac logic ([9755f5c](https://github.com/takehaya/xdperf/commit/9755f5ca7c2cea7d2ef86e40be2739a1a7d2b8cf))
* pkt entry size and lookup mac logic ([35b7d63](https://github.com/takehaya/xdperf/commit/35b7d6353bc199e6a2e0ead3818c7a7155352f09))

## [0.5.1](https://github.com/takehaya/xdperf/compare/v0.5.0...v0.5.1) (2025-11-29)


### 🐛 Bug Fixes

* ci code ([67e7cc8](https://github.com/takehaya/xdperf/commit/67e7cc8ffe46862239f0e565b5f18fc6d7576f90))
* ci code ([7fd7ce3](https://github.com/takehaya/xdperf/commit/7fd7ce3a2a087c4ff0c36175c4a6c1fb07f7d320))

## [0.5.0](https://github.com/takehaya/xdperf/compare/v0.4.0...v0.5.0) (2025-11-29)


### 🎉 Features

* implement variable template feature ([7ba8a49](https://github.com/takehaya/xdperf/commit/7ba8a49b74c5e18d931e9582a85366b2f6c45803))

## [0.4.0](https://github.com/takehaya/xdperf/compare/v0.3.0...v0.4.0) (2025-11-29)


### 🎉 Features

* add guest lib for neighborResolveFunc ([4274423](https://github.com/takehaya/xdperf/commit/4274423e0b88766e2b6d48840475829cf0505dfa))
* add guest lib for neighborResolveFunc ([3d84ee7](https://github.com/takehaya/xdperf/commit/3d84ee7c4850ba8806c76cb59b3cbbadf7fd5219))

## [0.3.0](https://github.com/takehaya/xdperf/compare/v0.2.0...v0.3.0) (2025-11-29)


### 🎉 Features

* add a new plugin iface define ([79efb50](https://github.com/takehaya/xdperf/commit/79efb500d452b67c1f8121d4e9a748ac31a57def))
* add debug log option ([e1274b8](https://github.com/takehaya/xdperf/commit/e1274b8796771c1739a0261d41eec0c2c34a1055))
* add debug log option ([830e0ec](https://github.com/takehaya/xdperf/commit/830e0ec70c27d3c167ae5c1731909b09710d8e10))
* add go plugin type ([c310c71](https://github.com/takehaya/xdperf/commit/c310c717d2a1c6716766f179e3905c1835b85629))
* add template engine ([c1ad24c](https://github.com/takehaya/xdperf/commit/c1ad24cc94231661e241d20d9a5e34a6532b2120))
* use go plugin ([4e77c6a](https://github.com/takehaya/xdperf/commit/4e77c6ae8c89a6acf4591e33462857d232deee20))


### 🐛 Bug Fixes

* add param for go plugin case ([8dd2474](https://github.com/takehaya/xdperf/commit/8dd247462cb1cc2b8c8a315a24ee064c4a20f05c))
* add param for go plugin case ([1762274](https://github.com/takehaya/xdperf/commit/1762274689f68a5e7fe3e77b1aee4d357c5f9bf5))


### 🔧 Miscellaneous Chores

* remove release for bpf build ([21a2b34](https://github.com/takehaya/xdperf/commit/21a2b344c0eefc10aea2d153547f8ff33e6813dc))


### ♻️ Code Refactoring

* modify all logic ([6ac791b](https://github.com/takehaya/xdperf/commit/6ac791b354129099b114340845cc4201fa901f6d))
* modify plugin call logic ([1307a61](https://github.com/takehaya/xdperf/commit/1307a61de4c986cd00f6063e71e1e74215a6d4e1))
* move to guest api file ([cde4193](https://github.com/takehaya/xdperf/commit/cde4193fdc2c02e4be91eb4c86afc597c7be8fc2))

## [0.2.0](https://github.com/takehaya/xdperf/compare/v0.1.3...v0.2.0) (2025-11-25)


### 🎉 Features

* add dummy xdp prog attach and add tips ([5432b76](https://github.com/takehaya/xdperf/commit/5432b767dd8bdcff06c1a6b782b04d5a08d3c8b4))
* add dummy xdp prog attach and add tips ([99b4576](https://github.com/takehaya/xdperf/commit/99b45763a1f2e66bde62e680184432af24a5f6cb))


### 🐛 Bug Fixes

* bpf verifyer bug fix ([40efd63](https://github.com/takehaya/xdperf/commit/40efd63b6d29cd12051e65bdc4a7dabb39ebe770))


### 🔧 Miscellaneous Chores

* add debug print option for bpf ([66a7622](https://github.com/takehaya/xdperf/commit/66a7622fdea8a805dff667e94b9114c0e2914190))
* add output iface ([3882a46](https://github.com/takehaya/xdperf/commit/3882a46611543b559c473ed7b1b121f2d5762f24))
* apply lint ([7bb26f7](https://github.com/takehaya/xdperf/commit/7bb26f72ae913edbb107f2cbc33fd3cabd0e36c4))
* out bpf gen ([e3937f6](https://github.com/takehaya/xdperf/commit/e3937f6fc8c505e04562c775a4d804bd1d2e5cc5))
* split target options ([f4da01b](https://github.com/takehaya/xdperf/commit/f4da01b598b885afc5427b77e08e6918c984997e))
* split target options ([d6af8a0](https://github.com/takehaya/xdperf/commit/d6af8a0c9a87dca008484d9f61bf390a868fce51))
* tiny fix ([18f0fb8](https://github.com/takehaya/xdperf/commit/18f0fb8a8ae6e32186845eaa8e4295a8c72929ab))


### ♻️ Code Refactoring

* add clang-fmt conf and fmt ([4fd4a40](https://github.com/takehaya/xdperf/commit/4fd4a402e3c7c7ad57a027c27ebe3a3ea2a2b1d9))
* add clang-fmt conf and fmt ([02a9c31](https://github.com/takehaya/xdperf/commit/02a9c31e3be6138288dfa35b1351c48b0d73ee21))

## [0.1.3](https://github.com/takehaya/xdperf/compare/v0.1.2...v0.1.3) (2025-11-22)


### 🐛 Bug Fixes

* add build flag ([ffcb237](https://github.com/takehaya/xdperf/commit/ffcb237faef6482f78a7247fdb9921f29762010c))
* add build flag ([df7d2a8](https://github.com/takehaya/xdperf/commit/df7d2a83f34092599703b7016d14d554f7b4d612))

## [0.1.2](https://github.com/takehaya/xdperf/compare/v0.1.1...v0.1.2) (2025-11-22)


### 🐛 Bug Fixes

* bpf gen build ([f985283](https://github.com/takehaya/xdperf/commit/f985283658d80a23d4297fe0d948a6437ea1b451))
* bpf gen build ([a10c1b3](https://github.com/takehaya/xdperf/commit/a10c1b3ae65047a9e514686676157d96b697a78f))

## [0.1.1](https://github.com/takehaya/xdperf/compare/v0.1.0...v0.1.1) (2025-11-03)


### 🔧 Miscellaneous Chores

* add xdperf installer script and docs ([bbc63e6](https://github.com/takehaya/xdperf/commit/bbc63e6a65cd46bb7b6d76f281d4ddef52b78e15))
* add xdperf installer script and docs ([b07d26e](https://github.com/takehaya/xdperf/commit/b07d26e3e7bc10299c9372015d09338e234cc1dc))

## [0.1.0](https://github.com/takehaya/xdperf/compare/v0.0.1...v0.1.0) (2025-11-03)


### 🎉 Features

* add cli base code ([c75e0f3](https://github.com/takehaya/xdperf/commit/c75e0f3c45bcfc803f0a9508c4ee40bacc0f52b4))
* add ebpf load and run ([f700f8e](https://github.com/takehaya/xdperf/commit/f700f8e609be86ee38b53d54231b37fb0ede9193))
* add logger pkg ([5441112](https://github.com/takehaya/xdperf/commit/5441112379d9503641b313459fceb49e5916fd6f))
* add plugin docs and sdk ([f4af483](https://github.com/takehaya/xdperf/commit/f4af483124c89d60c90e87c6a5174919d548b403))
* add plugin docs and sdk ([d5b744a](https://github.com/takehaya/xdperf/commit/d5b744ab8eb3ff986a94c60f98ef5e5e98a0677d))
* add simpleudp pkt plugin ([5210058](https://github.com/takehaya/xdperf/commit/5210058ca364718e6f08002d6e9df809b46a5a0b))
* add wasm plugin system ([ed1fdd8](https://github.com/takehaya/xdperf/commit/ed1fdd80166c2cdc58171ce07053d3800f52d527))
* add wasm plugin system ([232ff76](https://github.com/takehaya/xdperf/commit/232ff767795cb9845cfb283d82e8a3838b6e11eb))
* base code ([39fac19](https://github.com/takehaya/xdperf/commit/39fac198ddf8787d93f9ef46e6de1784288af3c2))
* init bpf build code ([4e78b54](https://github.com/takehaya/xdperf/commit/4e78b542ff3f32735b92ca4d5c580e4e482e2a99))
* use BPF_F_TEST_XDP_LIVE_FRAMES ([5ea70d7](https://github.com/takehaya/xdperf/commit/5ea70d7e1da19bf4433eadb539dba554ad0d70e1))


### 🔧 Miscellaneous Chores

* add dev and lint tool install ([5166bcc](https://github.com/takehaya/xdperf/commit/5166bcce428fae051961b682f3097c40bce4e643))
* add editor config ([08db875](https://github.com/takehaya/xdperf/commit/08db87532ddeb05d18478572a55da57450ce61f2))
* add flags ([f7ae442](https://github.com/takehaya/xdperf/commit/f7ae44229c15c5211b880e2dbb244fbd85301f74))
* add gitignore ([41ad219](https://github.com/takehaya/xdperf/commit/41ad219b462756f9061d6b0dc475eb6e242d7976))
* add goreleaser ([bcad2e3](https://github.com/takehaya/xdperf/commit/bcad2e354739eb673a3f47232c66afd589d814ac))
* add lefthook ([f7dabf1](https://github.com/takehaya/xdperf/commit/f7dabf1aa0abcbcddc4238e3459bc1c83c1c1dfe))
* add lint ([d771327](https://github.com/takehaya/xdperf/commit/d771327f0490ee6af1133b3b4a13729a93699114))
* add parse json ([40ed9a1](https://github.com/takehaya/xdperf/commit/40ed9a1235e13fd27d7050ded313ef22585c779c))
* add readme ([488bf12](https://github.com/takehaya/xdperf/commit/488bf12d1812b69621d9ff7cafa345544831e567))
* fmt c code ([611d077](https://github.com/takehaya/xdperf/commit/611d077ea69d17b2b2c6e7698b8a828a21a2d68b))
* modify pkg ([308e3a1](https://github.com/takehaya/xdperf/commit/308e3a1329ee103487ccf903c33a2630772cb40e))
* modify readme ([6bf901a](https://github.com/takehaya/xdperf/commit/6bf901a8233f2f112f356dda9121f645d41eabcb))
* remark wip ([4dcb3df](https://github.com/takehaya/xdperf/commit/4dcb3df6512a34bd185dbcd30a4766e9336b9f42))
* rename snapshot version template ([76e7fa8](https://github.com/takehaya/xdperf/commit/76e7fa87aaa9b82f5c87cdb6f097751b6d3713d5))
* set init version for 0.0.1 ([d8097ec](https://github.com/takehaya/xdperf/commit/d8097ec925770ecf8e8acd44d3c42ad2765de9db))
* set init version for 0.0.1 ([8415619](https://github.com/takehaya/xdperf/commit/8415619ff5032297aad3306ccde08c4f90ba00c9))
* tiny update ([028e941](https://github.com/takehaya/xdperf/commit/028e94127a87a3c4c420e4709e5a0199de65dbc4))
* update go version and refactor ([89b1d1d](https://github.com/takehaya/xdperf/commit/89b1d1da60dbb845a565f1b13b11436a7a6148e7))
