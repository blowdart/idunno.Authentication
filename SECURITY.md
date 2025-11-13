# Security Policy

## Supported Versions

Only the latest version of the libraries are supported.

| Version    | Supported          |
| ---------- | ------------------ |
| 3.0.0      | :white_check_mark: |
| <= 2.3.0   | :x:                |

## Reporting a Vulnerability

To report a vulnerability you can use GitHub's [private vulnerability reporting](https://github.com/blowdart/idunno.Authentication/security/advisories)
or via email to security@idunno.org.

I will try to acknowledge your email within 48 hours, but please keep in mind this is a "spare-time" project.
After the initial reply to your report, the security I will endeavor to keep you informed of how a fix is progressing
and when you can expect it to be delivered. I may ask for additional information on the bug.

Please reproduce your bug on the latest supported version published on nuget.org

## Disclosure Policy

When diagnosing and fixing a security bug the process is as follows:

  * Confirm the problem and determine the affected versions.
  * Audit code to find any potential similar problems.
  * Prepare fixes for the latest released package. 
  * Build and test fixes in private.
  * Release to nuget after successful testing.
  * Create advisory so dependabot and others will start notifications.

I would prefer report remain confidential until a fix is released, or I decide it is not an issue, but I acknowledge that some have other feelings about disclosure policies.
