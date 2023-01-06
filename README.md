# sw1tch

poc of CVE-2022-46689 written purely in swift

## Supported:
- iOS 16.0-16.1.2, 15.7.1 and below
- watchOS 9.1 and below (untested)
- tvOS 16.1.1 and below (untested)


*dont use this is its unstable, not my fault if your device gets damaged*


## Building (*OS)
- open xcode project
- build
- profit?


## Credits:
- [zhuowei](https://github.com/zhuowei/) for [MacDirtyCowDemo](https://github.com/zhuowei/MacDirtyCowDemo)
- [Apple](https://apple.com) for [vm_unaligned_copy_switch_race](https://github.com/apple-oss-distributions/xnu/blob/xnu-8792.61.2/tests/vm/vm_unaligned_copy_switch_race.c) test case
- [Ian Beer](https://twitter.com/i41nbeer) for finding [CVE-2022-46689](https://nvd.nist.gov/vuln/detail/CVE-2022-46689)

