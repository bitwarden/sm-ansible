# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/) and this project
adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.1] - 2024-09-17

### Fixed

-   Non-default API and Identity URLs being ignored (#45)

-   String interpolation error on failure to lookup secret by access token (#33)

### Changed

-   Use state file by default (#51)

-   Display a deprecation warning if using `bitwarden-sdk==0.1.0` Python package (#53)

## [1.0.0] - 2024-03

### Added

-   Ansible lookup plugin for fetching secrets from Bitwarden Secrets Manager.

[Unreleased]: https://github.com/bitwarden/sm-ansible/compare/v1.0.0...HEAD
