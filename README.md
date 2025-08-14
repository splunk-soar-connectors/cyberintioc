# Cyberint Splunk SOAR connector

Welcome to the open-source repository for Splunk SOAR's Cyberint IoC App.

## Cyberint IoC

Publisher: Check Point Cyberint \
Connector Version: 1.0.0 \
Product Vendor: Check Point Cyberint \
Product Name: Cyberint IoC \
Minimum Product Version: 6.4.0

Cyberint and Splunk SOAR integration is here to simplify and streamline indicators for Splunk SOAR, bring enriched threat intelligence from the Argos Edge™ Digital Risk Protection Platform into Splunk SOAR and automatically implement playbooks and incident processes.

### Configuration Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**API Base URL** | required | Base URL of the Cyberint API | string | `url`
**Access Token** | required | API Access Token for authentication | password |
**Company Name** | required | The name of the company | string |

### Supported Actions

[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration \
[ioc - enrich sha256](#action-ioc---enrich-sha256) - Enrich a SHA256 hash \
[ioc - enrich ipv4](#action-ioc---enrich-ipv4) - Enrich an IPv4 address \
[ioc - enrich url](#action-ioc---enrich-url) - Enrich a URL \
[ioc - enrich domain](#action-ioc---enrich-domain) - Enrich a domain \
[on poll](#action-on-poll) - Ingest the daily IOC feed

## action: 'test connectivity'

Validate the asset configuration for connectivity using supplied configuration

Type: **test** \
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

No Output

## action: 'ioc - enrich sha256'

Enrich a SHA256 hash

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**Hash** | required | SHA256 hash to enrich | string | `hash` `sha256`

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed
action_result.parameter.Hash | string | `hash` `sha256` |
action_result.message | string | |
summary.total_objects | numeric | | 1
summary.total_objects_successful | numeric | | 1

## action: 'ioc - enrich ipv4'

Enrich an IPv4 address

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**IP** | required | IPv4 address to enrich | string | `ip` `ipv4`

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed
action_result.parameter.IP | string | `ip` `ipv4` |
action_result.message | string | |
summary.total_objects | numeric | | 1
summary.total_objects_successful | numeric | | 1

## action: 'ioc - enrich url'

Enrich a URL

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**URL** | required | URL to enrich | string | `url`

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed
action_result.parameter.URL | string | `url` |
action_result.message | string | |
summary.total_objects | numeric | | 1
summary.total_objects_successful | numeric | | 1

## action: 'ioc - enrich domain'

Enrich a domain

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**Domain** | required | Domain to enrich | string | `domain`

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed
action_result.parameter.Domain | string | `domain` |
action_result.message | string | |
summary.total_objects | numeric | | 1
summary.total_objects_successful | numeric | | 1

## action: 'on poll'

Ingest the daily IOC feed

Type: **ingest** \
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

No Output

## Contributing

Please have a look at our [Contributing Guide](https://github.com/Splunk-SOAR-Apps/.github/blob/main/.github/CONTRIBUTING.md) for guidelines if you are interested in contributing, raising issues, or learning more about open-source SOAR apps.

Please also review our [Conventions](https://github.com/Splunk-SOAR-Apps/.github/blob/main/.github/CONTRIBUTING.md) to ensure you follow up-to-date standards.

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2025 Check Point Cyberint.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
