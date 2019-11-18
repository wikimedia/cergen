# 0.2.6

- Fix expiry datetime parsing from ISO-8601 string in manifest yaml.

# 0.2.5

- Improve error handling and logging when getting certificate from puppetmaster

- Differentiate between a non existent cert and an internal server error.

- Fix type in puppet-sign-cert script.

- Allow Java Trustores to have a separate password.

# 0.2.4
- Better error message when attempting to regenerate a Puppet signed certificate.

# 0.2.3
- Add support for keyUsage extensions.

# 0.2.2
- IP subject alternate names are now supported transparently.

# 0.2.1
- Now also generate ca.crt.pem files in each certificate directory.

# 0.2.0
- puppet-sign-cert now only works with Puppet 4.

# 0.1.1

- Support empty subjects.
  Certificate subject is now optional, but will always include CN.

- `--base-private-path` now defaults to the same location as --base-path.


# 0.1.0

- Initial version
