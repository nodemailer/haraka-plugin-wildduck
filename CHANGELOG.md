# Changelog

## [5.8.16](https://github.com/nodemailer/haraka-plugin-wildduck/compare/v5.8.15...v5.8.16) (2024-12-23)


### Bug Fixes

* **catchall-header:** ZMS-184 ([#49](https://github.com/nodemailer/haraka-plugin-wildduck/issues/49)) ([6ca9d00](https://github.com/nodemailer/haraka-plugin-wildduck/commit/6ca9d009966b860c201e8b0c7c24856263369c3e))

## [5.8.15](https://github.com/nodemailer/haraka-plugin-wildduck/compare/v5.8.14...v5.8.15) (2024-11-05)


### Bug Fixes

* **bimi:** Bumped mailauth for BIMI CMC support ([94ad9f4](https://github.com/nodemailer/haraka-plugin-wildduck/commit/94ad9f4414d7ce65ef34f1c5364393e4cefd9840))

## [5.8.14](https://github.com/nodemailer/haraka-plugin-wildduck/compare/v5.8.13...v5.8.14) (2024-10-28)


### Bug Fixes

* **cicd-pipeline:** Docker setup release ([#43](https://github.com/nodemailer/haraka-plugin-wildduck/issues/43)) ([691aed5](https://github.com/nodemailer/haraka-plugin-wildduck/commit/691aed559eb40778fdda20956c8cf7b3f9c11d01))
* **deps:** Bumped dependencies ([5472b04](https://github.com/nodemailer/haraka-plugin-wildduck/commit/5472b04dce3a368819dd49ddbfca07df0706db90))
* **license-readme-copyright:** ZMS-180 ([#47](https://github.com/nodemailer/haraka-plugin-wildduck/issues/47)) ([57e68aa](https://github.com/nodemailer/haraka-plugin-wildduck/commit/57e68aacfda4d0281883bcbb2b5da5b3d30100db))
* **log-filecontenthash:** add attachment file content hash logging through graylog ZMS-176 ([#45](https://github.com/nodemailer/haraka-plugin-wildduck/issues/45)) ([1fabcf4](https://github.com/nodemailer/haraka-plugin-wildduck/commit/1fabcf4e4616469a9a9103cb4d087db04b890c5f))
* **log-headerfromvalue:** graylog header from value should be MIME decoded before logging ZMS-138 ([#46](https://github.com/nodemailer/haraka-plugin-wildduck/issues/46)) ([11f71a0](https://github.com/nodemailer/haraka-plugin-wildduck/commit/11f71a05c7532ad7c581232640e73b722bb55563))
* **logs:** Log quota information when account over quota ([b1ba829](https://github.com/nodemailer/haraka-plugin-wildduck/commit/b1ba829cd91ea5d34ae38b29ed1615a30b86b9a8))

## [5.8.13](https://github.com/nodemailer/haraka-plugin-wildduck/compare/v5.8.12...v5.8.13) (2024-08-08)


### Bug Fixes

* **auth-spf:** ZMS-165. if remote IP is private default to softfail with custom message ([#42](https://github.com/nodemailer/haraka-plugin-wildduck/issues/42)) ([0198c4f](https://github.com/nodemailer/haraka-plugin-wildduck/commit/0198c4fa6a3518cf2356ea3bf86e0081e93a5540))
* Bumped deps ([21a9934](https://github.com/nodemailer/haraka-plugin-wildduck/commit/21a99345a723b6b441b07dde5c8bb46c0b549ebc))
* **connection-object:** remove_ip -&gt; remove.ip. Otherwise shows undefined ([#40](https://github.com/nodemailer/haraka-plugin-wildduck/issues/40)) ([24a6a20](https://github.com/nodemailer/haraka-plugin-wildduck/commit/24a6a2077d8390de36c40f1f8be46e3a33485e04))

## [5.8.12](https://github.com/nodemailer/haraka-plugin-wildduck/compare/v5.8.11...v5.8.12) (2024-04-22)


### Bug Fixes

* **deps:** Bumped WildDuck ([3b496f8](https://github.com/nodemailer/haraka-plugin-wildduck/commit/3b496f8b2ad814b4acdc3670eea6dd775125032a))

## [5.8.11](https://github.com/nodemailer/haraka-plugin-wildduck/compare/v5.8.10...v5.8.11) (2024-04-19)


### Bug Fixes

* **eslint:** Lock eslint version to v8 ([6b93f19](https://github.com/nodemailer/haraka-plugin-wildduck/commit/6b93f19a5eb3b189c92170138bf5bc8f6ec1a762))
* init_wildduck_transaction in index, in case hook_mail not run ([#33](https://github.com/nodemailer/haraka-plugin-wildduck/issues/33)) ([30374bd](https://github.com/nodemailer/haraka-plugin-wildduck/commit/30374bd3621f723ee6069eb5f5a6bdfff68c9934))
* **logging:** If DMARC was missing, then logging failed with an error ([830ad7d](https://github.com/nodemailer/haraka-plugin-wildduck/commit/830ad7dfe7c0f38949d90d7a9ca97a3c22f0065d))

## [5.8.10](https://github.com/nodemailer/haraka-plugin-wildduck/compare/v5.8.9...v5.8.10) (2024-04-01)


### Bug Fixes

* **deps:** Bumped wildduck from 1.42.1 to 1.42.5 ([a97d048](https://github.com/nodemailer/haraka-plugin-wildduck/commit/a97d048ee240afa219adaf2d58c08c655bf66aeb))

## [5.8.9](https://github.com/nodemailer/haraka-plugin-wildduck/compare/v5.8.8...v5.8.9) (2024-02-12)


### Bug Fixes

* **logs:** do not log entire received chain ([102b4b0](https://github.com/nodemailer/haraka-plugin-wildduck/commit/102b4b0268c97c575090db38700e9ad02a03c26a))
* **logs:** Log received chain comments ([#28](https://github.com/nodemailer/haraka-plugin-wildduck/issues/28)) ([3633ed2](https://github.com/nodemailer/haraka-plugin-wildduck/commit/3633ed20548ba1ff91fa1c0c8ac2b23c63d8886e))

## [5.8.8](https://github.com/nodemailer/haraka-plugin-wildduck/compare/v5.8.7...v5.8.8) (2024-02-08)


### Bug Fixes

* **logs:** added bimi and dmarc entries for dkim logs to graylog ([dca10a0](https://github.com/nodemailer/haraka-plugin-wildduck/commit/dca10a02b9e765327ee506ca7549b5d5e3911333))

## [5.8.7](https://github.com/nodemailer/haraka-plugin-wildduck/compare/v5.8.6...v5.8.7) (2024-02-05)


### Bug Fixes

* **deps:** bumped deps for fixes ([a527c41](https://github.com/nodemailer/haraka-plugin-wildduck/commit/a527c41bf74cdbc2d223d1bfca468094b0db1d76))

## [5.8.6](https://github.com/nodemailer/haraka-plugin-wildduck/compare/v5.8.5...v5.8.6) (2024-01-26)


### Bug Fixes

* **deps:** bumped mailauth ([7fc7781](https://github.com/nodemailer/haraka-plugin-wildduck/commit/7fc77814615c6426915778a79b5c366ec9c494a9))

## [5.8.5](https://github.com/nodemailer/haraka-plugin-wildduck/compare/v5.8.4...v5.8.5) (2024-01-25)


### Bug Fixes

* **dkim:** Log spf results in dkim signature log rows ([d93ae97](https://github.com/nodemailer/haraka-plugin-wildduck/commit/d93ae973b756271850f837d4897417910834485e))

## [5.8.4](https://github.com/nodemailer/haraka-plugin-wildduck/compare/v5.8.3...v5.8.4) (2024-01-25)


### Bug Fixes

* **dkim:** added additional dkim log entries ([bed5a64](https://github.com/nodemailer/haraka-plugin-wildduck/commit/bed5a640b041fe8370afa9dd55e83ae2ed67bee7))

## [5.8.3](https://github.com/nodemailer/haraka-plugin-wildduck/compare/v5.8.2...v5.8.3) (2024-01-25)


### Bug Fixes

* **dkim:** Log dkim signatures ([89a0b0b](https://github.com/nodemailer/haraka-plugin-wildduck/commit/89a0b0bbec4cca5a2b12f620d04220d01771915b))
* **mbix_full:** Return a hard bounce for full mailbox ([d596226](https://github.com/nodemailer/haraka-plugin-wildduck/commit/d59622638b5599418ff062d5bd2ace1011c17f02))

## [5.8.2](https://github.com/nodemailer/haraka-plugin-wildduck/compare/v5.8.1...v5.8.2) (2023-10-17)


### Bug Fixes

* **deps:** Bumped dependencies ([def43fb](https://github.com/nodemailer/haraka-plugin-wildduck/commit/def43fb9eaee7ac4ab76ccb91f38a33c41693d4f))

## [5.8.1](https://github.com/nodemailer/haraka-plugin-wildduck/compare/v5.8.0...v5.8.1) (2023-09-05)


### Bug Fixes

* **ci:** Added CI test runner and release builder ([d575511](https://github.com/nodemailer/haraka-plugin-wildduck/commit/d5755118a904a35d2737c63b2780cb5151f55a22))
* **release:** added package-lock required for publishing ([12e2af8](https://github.com/nodemailer/haraka-plugin-wildduck/commit/12e2af890d3072e175b47e230241114a57487ea7))
