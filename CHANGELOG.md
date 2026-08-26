# Changelog

## Unreleased

- Added a GitHub Actions security workflow: CodeQL for Actions YAML, Semgrep SARIF scanning for PHP, and Markdown/SARIF reports.
- Published the repository under `jeff1121/librenms-cisco-wlc-ap-monitor`.

## 1.2.0 - 2026-07-22

- Added update-safe installation through `lnms plugin:add` and `composer.plugins.json`.
- Added dashboard widget route and Notes-widget embed example.
- Fixed widget SQL ambiguity when filtering by `device_id`.
- Added support for LibreNMS automatic `-H` service-check argument.
- Corrected Nagios plugin installation path and added extensionless symlink.
- Added install, update, health-check, backup, restore and uninstall tooling.
- Added documentation for new installs, LibreNMS upgrades, server migration, alerts, dashboard integration and GitHub publishing.

## 1.1.0

- Added compact dashboard widget.

## 1.0.0

- Initial AP inventory persistence, state tracking, GUI and service check.
