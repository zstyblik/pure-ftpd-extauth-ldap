# [pure-ftpd] external auth plugin - LDAP + supplementary groups

External LDAP authentication script for pure-ftpd with support for checking of
group membership

## Features:
- adds support of suplementary groups [andreas]
- straight/proxy auth against LDAP server
- access to passwords is not needed by the proxy user
- LDAP/LDAPS/TLS is supported
- required group(s)

## Missing features:
- *annonymous* *binds* to LDAP *are* currently *unsupported*
- quotas and whatever additional features

## Requirements:
- pure-ftpd v1.0.2(1|2) or newer
- patch from http://pelme.se/~andreas/code/pure-ftpd-auth/
- LDAP server, this script, common things

## Motivation:
- pure-ftpd seemed to be buggy with shadow && nss-ldap
- LDAP authentication *should* *not* be done the way it's in
  pure-ftpd LDAP auth module [that's the view of OpenLDAP community]
- we needed this, of course [have you expected something else?]

## Licence:
- GNU/GPLv3, Mozilla...I somewhat don't care too much. If you find
  it usefull, let me know.

## Notes:

### Straight bind
Straight bind will be always problematic in a way that you need to
know DN. You can construct DN from user's input or somehow, but
it's not reliable, problematic, whatever.
Eg. user@people.domain.tld=>uid=user,ou=people,dc=domain,dc=tld.

### Proxy bind
Proxy bind is somewhat easier. You use proxy user to find DN by
some criteria and try to auth against it with credentials user provided.


Please note, I presume your user accounts are located in
ou=people+ldapBaseDN and UID is uid=username! If this differs,
you need to change ldapUidBaseDN.

Please note, I presume your groups are located in
ou=group+ldapBaseDN and these are object type of posixGroup.
If this differs, you need to change ldapGidBaseDN.

Authenticated user must have read access to ou=group! If this isn't the
case, allow access or hack the script up [unbind user
&& bind proxy].


Thank you again, Andreas!

"YO, ADRIAN! I DID IT!"

2009/07/23 @ Zdenek Styblik

```
user_quota_size:xxx
user_quota_files:xxx
per_user_max:xxx
```
