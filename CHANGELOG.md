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
