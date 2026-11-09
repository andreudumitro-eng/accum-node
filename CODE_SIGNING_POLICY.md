# Code Signing Policy

Free code signing provided by SignPath.io, certificate by SignPath Foundation.

## Project
This policy applies to the ACCUM project (repository: andreudumitro-eng/accum-node).

## Roles and Responsibilities
- **Committers/Reviewers**: The project maintainer(s) responsible for the source code and build scripts.
- **Approvers**: The maintainer(s) who will manually approve each signing request in the SignPath dashboard.

## Process
- Only binaries built by the project's GitHub Actions CI from the public source code in this repository will be submitted for signing.
- No third-party or proprietary binaries will be signed with this project's certificate.
- Every production signing request requires manual approval by an approver.
- All project members with access to the repository or signing dashboard must use Multi-Factor Authentication (MFA).

## Privacy
The software does not collect or transmit user data to external servers without explicit user consent. System changes and uninstallation instructions are documented in the project's README.
