# Changelog

## [0.3.2](https://github.com/hairyhenderson/sagemcom_fast_exporter/compare/v0.3.1...v0.3.2) (2025-07-13)


### Dependencies

* **docker:** Bump alpine from 3.21 to 3.22 ([#155](https://github.com/hairyhenderson/sagemcom_fast_exporter/issues/155)) ([6d99cd2](https://github.com/hairyhenderson/sagemcom_fast_exporter/commit/6d99cd2a133c0591a72ee7fe94ea6f7d4d6c5543))
* **go:** Bump github.com/prometheus/client_golang from 1.21.1 to 1.22.0 ([#149](https://github.com/hairyhenderson/sagemcom_fast_exporter/issues/149)) ([35765ce](https://github.com/hairyhenderson/sagemcom_fast_exporter/commit/35765ce7a44c815a4a0f062e4d8f1920f5362da8))
* **go:** Bump github.com/prometheus/common from 0.64.0 to 0.65.0 ([#156](https://github.com/hairyhenderson/sagemcom_fast_exporter/issues/156)) ([282acc1](https://github.com/hairyhenderson/sagemcom_fast_exporter/commit/282acc196d22dfe438202b5e93f8f26f2cd60f02))
* **go:** Bump the otel group across 1 directory with 6 updates ([#154](https://github.com/hairyhenderson/sagemcom_fast_exporter/issues/154)) ([7e18bba](https://github.com/hairyhenderson/sagemcom_fast_exporter/commit/7e18bba05813bd439f1bae899d033d9266d32ce2))
* **go:** Bump the otel group with 6 updates ([#157](https://github.com/hairyhenderson/sagemcom_fast_exporter/issues/157)) ([568e553](https://github.com/hairyhenderson/sagemcom_fast_exporter/commit/568e553e436198abab5688e53d86e4c63bb0895b))

## [0.3.1](https://github.com/hairyhenderson/sagemcom_fast_exporter/compare/v0.3.0...v0.3.1) (2025-04-07)


### Bug Fixes

* **types:** Ignore SetIPTVInterface which can't be marshaled ([#145](https://github.com/hairyhenderson/sagemcom_fast_exporter/issues/145)) ([4b727cf](https://github.com/hairyhenderson/sagemcom_fast_exporter/commit/4b727cf6d9e32ac6173d374671acfe473e6c81eb))


### Documentation

* Add section about compatibility to README ([#147](https://github.com/hairyhenderson/sagemcom_fast_exporter/issues/147)) ([1798f89](https://github.com/hairyhenderson/sagemcom_fast_exporter/commit/1798f89639cfe54439072d5dfe68583fb0a679a8))


### Dependencies

* **actions:** Bump actions/create-github-app-token in the actions group ([#144](https://github.com/hairyhenderson/sagemcom_fast_exporter/issues/144)) ([b6c3d88](https://github.com/hairyhenderson/sagemcom_fast_exporter/commit/b6c3d884db1484578fb7c40e56697e779ed887ed))
* **go:** Bump github.com/prometheus/common from 0.62.0 to 0.63.0 ([#142](https://github.com/hairyhenderson/sagemcom_fast_exporter/issues/142)) ([78f6191](https://github.com/hairyhenderson/sagemcom_fast_exporter/commit/78f6191a5813a6fa124aee395103968c8bc3721e))
* **go:** Bump golang.org/x/net from 0.35.0 to 0.36.0 ([#141](https://github.com/hairyhenderson/sagemcom_fast_exporter/issues/141)) ([968e581](https://github.com/hairyhenderson/sagemcom_fast_exporter/commit/968e581a2c8a5c446ab9b76d7f269456eea572fd))

## [0.3.0](https://github.com/hairyhenderson/sagemcom_fast_exporter/compare/v0.2.1...v0.3.0) (2025-03-07)


### Features

* **metrics:** Add traceID exemplar to scrape duration histogram ([#121](https://github.com/hairyhenderson/sagemcom_fast_exporter/issues/121)) ([9dff72a](https://github.com/hairyhenderson/sagemcom_fast_exporter/commit/9dff72affc05a789a8bdf7766837f2a91af73e1f))


### Dependencies

* **docker:** Bump golang from 1.23-alpine to 1.24-alpine ([#130](https://github.com/hairyhenderson/sagemcom_fast_exporter/issues/130)) ([a2faeaa](https://github.com/hairyhenderson/sagemcom_fast_exporter/commit/a2faeaaa87697fd2bd3cce77319b8e82647d11f0))
* **go:** Bump the otel group with 6 updates ([#140](https://github.com/hairyhenderson/sagemcom_fast_exporter/issues/140)) ([aa19d09](https://github.com/hairyhenderson/sagemcom_fast_exporter/commit/aa19d09a05fd2941983ac551c9f7363436996283))

## [0.2.1](https://github.com/hairyhenderson/sagemcom_fast_exporter/compare/v0.2.0...v0.2.1) (2024-12-23)


### Bug Fixes

* **types:** Correct field order breaking requests ([#119](https://github.com/hairyhenderson/sagemcom_fast_exporter/issues/119)) ([7e9ef44](https://github.com/hairyhenderson/sagemcom_fast_exporter/commit/7e9ef4438e368e933d1731cd3af6a708f44e8cf3))

## [0.2.0](https://github.com/hairyhenderson/sagemcom_fast_exporter/compare/v0.1.4...v0.2.0) (2024-12-21)


### Features

* **traces:** Use autoexport to configure OTel exporter ([#116](https://github.com/hairyhenderson/sagemcom_fast_exporter/issues/116)) ([bcbc8bc](https://github.com/hairyhenderson/sagemcom_fast_exporter/commit/bcbc8bc19eec12679f7c5b8e0c035ab6ab2db719))

## [0.1.4](https://github.com/hairyhenderson/sagemcom_fast_exporter/compare/v0.1.3...v0.1.4) (2024-12-16)


### Dependencies

* **docker:** Bump alpine from 3.20 to 3.21 ([#107](https://github.com/hairyhenderson/sagemcom_fast_exporter/issues/107)) ([3157825](https://github.com/hairyhenderson/sagemcom_fast_exporter/commit/3157825ff6f7159953d74412984331f5126ecf80))
* **go:** Bump github.com/prometheus/common from 0.60.1 to 0.61.0 ([#106](https://github.com/hairyhenderson/sagemcom_fast_exporter/issues/106)) ([dce11aa](https://github.com/hairyhenderson/sagemcom_fast_exporter/commit/dce11aaa82733f9288d30515a034b854b15ad0a2))
* **go:** Bump go.opentelemetry.io/contrib/instrumentation/net/http/httptrace/otelhttptrace ([#110](https://github.com/hairyhenderson/sagemcom_fast_exporter/issues/110)) ([3c58923](https://github.com/hairyhenderson/sagemcom_fast_exporter/commit/3c589235ebd967e9480c5faa1f710b11a1a2cd7d))
* **go:** Bump go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp ([#114](https://github.com/hairyhenderson/sagemcom_fast_exporter/issues/114)) ([05ee019](https://github.com/hairyhenderson/sagemcom_fast_exporter/commit/05ee019dad7620379f68c21113ab8693cdaa2d8d))
* **go:** Bump go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc ([#112](https://github.com/hairyhenderson/sagemcom_fast_exporter/issues/112)) ([7c47621](https://github.com/hairyhenderson/sagemcom_fast_exporter/commit/7c47621b4aaf959474cdf669b9e934bbc7696cf8))
* **go:** Bump go.opentelemetry.io/otel/sdk from 1.32.0 to 1.33.0 ([#113](https://github.com/hairyhenderson/sagemcom_fast_exporter/issues/113)) ([92c6006](https://github.com/hairyhenderson/sagemcom_fast_exporter/commit/92c6006b33372594fa54373fec4e9a2a44cd9773))

## [0.1.3](https://github.com/hairyhenderson/sagemcom_fast_exporter/compare/v0.1.2...v0.1.3) (2024-11-12)


### Dependencies

* **go:** Bump go.opentelemetry.io/contrib/instrumentation/net/http/httptrace/otelhttptrace ([#99](https://github.com/hairyhenderson/sagemcom_fast_exporter/issues/99)) ([0db0012](https://github.com/hairyhenderson/sagemcom_fast_exporter/commit/0db0012c37fdcdf1cd3340e82e3502500f23d7ef))
* **go:** Bump go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc ([#101](https://github.com/hairyhenderson/sagemcom_fast_exporter/issues/101)) ([927f6dc](https://github.com/hairyhenderson/sagemcom_fast_exporter/commit/927f6dcf7bd9f678db7650b1e10dfdba6c59d850))

## [0.1.2](https://github.com/hairyhenderson/sagemcom_fast_exporter/compare/v0.1.1...v0.1.2) (2024-10-25)


### Dependencies

* **docker:** Bump golang from 1.22-alpine to 1.23-alpine ([#68](https://github.com/hairyhenderson/sagemcom_fast_exporter/issues/68)) ([7adaf52](https://github.com/hairyhenderson/sagemcom_fast_exporter/commit/7adaf529b2a76e60fa9889e081518cc669c0df1a))
* **go:** Bump github.com/prometheus/client_golang from 1.19.1 to 1.20.2 ([#72](https://github.com/hairyhenderson/sagemcom_fast_exporter/issues/72)) ([ddb1898](https://github.com/hairyhenderson/sagemcom_fast_exporter/commit/ddb18988bd2b3c5299c4a19506d2504748d9c427))
* **go:** Bump github.com/prometheus/client_golang from 1.20.2 to 1.20.3 ([#81](https://github.com/hairyhenderson/sagemcom_fast_exporter/issues/81)) ([ab9f112](https://github.com/hairyhenderson/sagemcom_fast_exporter/commit/ab9f112eb638229076887ad655069321e37aae49))
* **go:** Bump github.com/prometheus/client_golang from 1.20.3 to 1.20.4 ([#89](https://github.com/hairyhenderson/sagemcom_fast_exporter/issues/89)) ([e994d4f](https://github.com/hairyhenderson/sagemcom_fast_exporter/commit/e994d4fc2f0d387b636e0bf79949927f15a09d61))
* **go:** Bump github.com/prometheus/client_golang from 1.20.4 to 1.20.5 ([#97](https://github.com/hairyhenderson/sagemcom_fast_exporter/issues/97)) ([0e2f08f](https://github.com/hairyhenderson/sagemcom_fast_exporter/commit/0e2f08f9427c9982457f6cc21bdaf96295bc5f4c))
* **go:** Bump github.com/prometheus/common from 0.54.0 to 0.55.0 ([#59](https://github.com/hairyhenderson/sagemcom_fast_exporter/issues/59)) ([7ecc5c7](https://github.com/hairyhenderson/sagemcom_fast_exporter/commit/7ecc5c7e88523ca02570a6da76627c5eebd04d1a))
* **go:** Bump github.com/prometheus/common from 0.55.0 to 0.57.0 ([#79](https://github.com/hairyhenderson/sagemcom_fast_exporter/issues/79)) ([321ebe5](https://github.com/hairyhenderson/sagemcom_fast_exporter/commit/321ebe591be75e648d38947e40f8f2f46e4b6c69))
* **go:** Bump github.com/prometheus/common from 0.57.0 to 0.59.1 ([#82](https://github.com/hairyhenderson/sagemcom_fast_exporter/issues/82)) ([045dda8](https://github.com/hairyhenderson/sagemcom_fast_exporter/commit/045dda8bb9d44084b557b73fd60f383616cd9850))
* **go:** Bump github.com/prometheus/common from 0.59.1 to 0.60.0 ([#90](https://github.com/hairyhenderson/sagemcom_fast_exporter/issues/90)) ([009618a](https://github.com/hairyhenderson/sagemcom_fast_exporter/commit/009618a050db9e1eed8792980c44bd2122e347af))
* **go:** Bump github.com/prometheus/common from 0.60.0 to 0.60.1 ([#98](https://github.com/hairyhenderson/sagemcom_fast_exporter/issues/98)) ([304fbc5](https://github.com/hairyhenderson/sagemcom_fast_exporter/commit/304fbc5bea0902453aeafdaa64d65fe7a531f1c0))
* **go:** Bump go.opentelemetry.io/contrib/instrumentation/net/http/httptrace/otelhttptrace ([#65](https://github.com/hairyhenderson/sagemcom_fast_exporter/issues/65)) ([e3c46d7](https://github.com/hairyhenderson/sagemcom_fast_exporter/commit/e3c46d7c7a754f5c0a207fc297fcc7ae295a193f))
* **go:** Bump go.opentelemetry.io/contrib/instrumentation/net/http/httptrace/otelhttptrace ([#73](https://github.com/hairyhenderson/sagemcom_fast_exporter/issues/73)) ([4dd47af](https://github.com/hairyhenderson/sagemcom_fast_exporter/commit/4dd47afdf963f3714c0138bfb39352f5788d6b09))
* **go:** Bump go.opentelemetry.io/contrib/instrumentation/net/http/httptrace/otelhttptrace ([#88](https://github.com/hairyhenderson/sagemcom_fast_exporter/issues/88)) ([3b0c7ed](https://github.com/hairyhenderson/sagemcom_fast_exporter/commit/3b0c7edb9e8c8aa34b5fe2970226fe8bc9998d79))
* **go:** Bump go.opentelemetry.io/contrib/instrumentation/net/http/httptrace/otelhttptrace ([#95](https://github.com/hairyhenderson/sagemcom_fast_exporter/issues/95)) ([9636499](https://github.com/hairyhenderson/sagemcom_fast_exporter/commit/9636499e734efcdc949f05547fda1ab7d04cb1e9))
* **go:** Bump go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp ([#76](https://github.com/hairyhenderson/sagemcom_fast_exporter/issues/76)) ([3a1e6f3](https://github.com/hairyhenderson/sagemcom_fast_exporter/commit/3a1e6f3b3cb777769ff40c5603dce865790ae417))
* **go:** Bump go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp ([#87](https://github.com/hairyhenderson/sagemcom_fast_exporter/issues/87)) ([fd01a64](https://github.com/hairyhenderson/sagemcom_fast_exporter/commit/fd01a64451081b5485360c67554184a3a96b1534))
* **go:** Bump go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp ([#96](https://github.com/hairyhenderson/sagemcom_fast_exporter/issues/96)) ([29c5e7a](https://github.com/hairyhenderson/sagemcom_fast_exporter/commit/29c5e7aa7d831921bb3a70ae9e513db1899bd7d0))
* **go:** Bump go.opentelemetry.io/otel from 1.28.0 to 1.29.0 ([#75](https://github.com/hairyhenderson/sagemcom_fast_exporter/issues/75)) ([f99e790](https://github.com/hairyhenderson/sagemcom_fast_exporter/commit/f99e7908ba969df060166df0abdbf4f9013d5b44))
* **go:** Bump go.opentelemetry.io/otel from 1.29.0 to 1.30.0 ([#85](https://github.com/hairyhenderson/sagemcom_fast_exporter/issues/85)) ([34cf881](https://github.com/hairyhenderson/sagemcom_fast_exporter/commit/34cf881ffe7d82a57eac0ec949dc9050a8c06e69))
* **go:** Bump go.opentelemetry.io/otel from 1.30.0 to 1.31.0 ([#93](https://github.com/hairyhenderson/sagemcom_fast_exporter/issues/93)) ([1798958](https://github.com/hairyhenderson/sagemcom_fast_exporter/commit/1798958eeda0a6d919984076e6ee205d0709cd26))
* **go:** Bump go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc ([#62](https://github.com/hairyhenderson/sagemcom_fast_exporter/issues/62)) ([2f9b891](https://github.com/hairyhenderson/sagemcom_fast_exporter/commit/2f9b89100771f76e7c70d56da242e9860360ed0a))
* **go:** Bump go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc ([#71](https://github.com/hairyhenderson/sagemcom_fast_exporter/issues/71)) ([3604883](https://github.com/hairyhenderson/sagemcom_fast_exporter/commit/36048833cc10f8c4f90c422886b2f0765c9a4390))
* **go:** Bump go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc ([#83](https://github.com/hairyhenderson/sagemcom_fast_exporter/issues/83)) ([c901062](https://github.com/hairyhenderson/sagemcom_fast_exporter/commit/c901062b47c34c3a4fee173eb5c0745ded1377fa))
* **go:** Bump go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc ([#94](https://github.com/hairyhenderson/sagemcom_fast_exporter/issues/94)) ([f201625](https://github.com/hairyhenderson/sagemcom_fast_exporter/commit/f2016259c3116e7154545cbf68293a0f420ccdac))
* **go:** Bump go.opentelemetry.io/otel/sdk from 1.29.0 to 1.30.0 ([#86](https://github.com/hairyhenderson/sagemcom_fast_exporter/issues/86)) ([7f6d389](https://github.com/hairyhenderson/sagemcom_fast_exporter/commit/7f6d389be36705e0219010c1b8357bd3d02e62c2))
* **go:** Bump go.opentelemetry.io/otel/sdk from 1.30.0 to 1.31.0 ([#91](https://github.com/hairyhenderson/sagemcom_fast_exporter/issues/91)) ([e647a21](https://github.com/hairyhenderson/sagemcom_fast_exporter/commit/e647a2141fa262c6dc985c5c2cd3b72ed3d9e199))
* **go:** Bump go.opentelemetry.io/otel/trace from 1.29.0 to 1.30.0 ([#84](https://github.com/hairyhenderson/sagemcom_fast_exporter/issues/84)) ([5d8b5e7](https://github.com/hairyhenderson/sagemcom_fast_exporter/commit/5d8b5e7062e53722ac05126758ed2ec9f162c779))
* **go:** Bump google.golang.org/grpc from 1.64.0 to 1.64.1 ([#67](https://github.com/hairyhenderson/sagemcom_fast_exporter/issues/67)) ([31222a6](https://github.com/hairyhenderson/sagemcom_fast_exporter/commit/31222a6b60ff5e6d10b6bef623964765f40cd788))

## [0.1.1](https://github.com/hairyhenderson/sagemcom_fast_exporter/compare/v0.1.0...v0.1.1) (2024-06-08)


### Dependencies

* **docker:** bump alpine from 3.19 to 3.20 ([#53](https://github.com/hairyhenderson/sagemcom_fast_exporter/issues/53)) ([497348c](https://github.com/hairyhenderson/sagemcom_fast_exporter/commit/497348c116b87c3030260b66314fbf19939c2565))
* **go:** Bump github.com/prometheus/common from 0.53.0 to 0.54.0 ([#57](https://github.com/hairyhenderson/sagemcom_fast_exporter/issues/57)) ([799d0bc](https://github.com/hairyhenderson/sagemcom_fast_exporter/commit/799d0bca1a5b6c00a9069330078c48973e672ebd))
