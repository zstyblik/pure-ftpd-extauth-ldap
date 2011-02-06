#!/usr/bin/perl
# [pure-ftpd] external auth plugin - LDAP+supplementary groups
#
# Features:
# - adds support of suplementary groups [andreas]
# - straight/proxy auth against LDAP server
# - access to passwords is not needed by the proxy user
# - LDAP/LDAPS/TLS is supported
# - required group(s)
# Missing features:
# - *annonymous* *binds* to LDAP *are* currently *unsupported*
# - quotas and whatever additional features
# Requirements:
# - pure-ftpd v1.0.2(1|2)
# - patch from 'http://pelme.se/~andreas/code/pure-ftpd-auth/'
# - LDAP server, this script, common things
# Motivation:
# - pure-ftpd seemed to be buggy with shadow && nss-ldap
# - LDAP authentication *should* *not* be done the way it's in 
#   pure-ftpd LDAP auth module [by the OpenLDAP community]
# - we needed this, of course [have you expected something else?]
# Licence:
# - GNU/GPLv3, Mozilla...I somewhat don't care too much. If you find 
#   it usefull, let me know.
# 
# Changes:
# 11/06/02 - add support for req. groups
# 09/23/07 - initial release
#
# ** Straight bind
# Straight bind will be always problematic in the way you need to 
# know DN. You can construct DN from user input, or somehow, but 
# it's not reliable, problematic, whatever.
# eg. user@people.domain.tld=>uid=user,ou=people,dc=domain,dc=tld.
#
# ** Proxy bind
# Proxy bind is somewhat easier. You use proxy user to find DN by 
# some criteria and try to auth against it by user provided 
# credentials.
#
#
# Please note, I presume your user accounts are located in 
# ou=people+ldapBaseDN and UID is uid=username! If it differs, 
# you need to change ldapUidBaseDN.
#
# Please note, I presume your groups are located in 
# ou=group+ldapBaseDN and these are object type of posixGroup.
# If it differs, you need to change ldapGidBaseDN.
#
# Authenticated user has read access to ou=group! If that's not the 
# case, allow access or hack the script up [unbind user 
# && bind proxy].
#
#
# Thank you again, andreas!
#
# "YO, ADRIAN! I DID IT!"
#
# 2009/07/23 @ Zdenek Styblik
#
# user_quota_size:xxx
# user_quota_files:xxx
# per_user_max:xxx
#
use strict;
use warnings;
use Net::LDAP;
use Net::LDAP::Constant;

my $ldapHost = "ldap://localhost/";
my $ldapPort = 389;
my $ldapTLS = 1;
my $ldapVersion = 3;
my $ldapBindDN = 'cn=proxy,dc=domain,dc=tld';
my $ldapPasswd = 'secret';
my $ldapBaseDN = "dc=domain,dc=tld";
my $ldapUidBaseDN = "ou=people";
my $ldapUidFilter = "(&(objectClass=posixAccount)(uid=%s))";
my $ldapGidBaseDN = "ou=group";
my $ldapGidFilter = "(&(objectClass=posixGroup)(memberUid=%s))";
my @reqLdapGroups = qw(); # put GID(s) in here!

sub authFail {
	printf("auth_ok:-1\n");
	printf("end\n");
	exit;
} # authFail

sub authOk {
	my ($uid, $gid, $dir, @groups) = @_;
	printf("auth_ok:1\n");
	printf("uid:%s\n", $uid);
	printf("gid:%s\n", $gid);
	printf("dir:%s\n", $dir);
	if (@groups > 0) {
		my $groupsStr = join(",", @groups);
		printf("groups:%s\n", $groupsStr);
	}
	printf("end\n");
} # authOk


my $login = $ENV{'AUTHD_ACCOUNT'} || undef;
my $passwd = $ENV{'AUTHD_PASSWORD'} || undef;
my $ipLocal = $ENV{'AUTHD_LOCAL_IP'} || undef;
my $portLocal = $ENV{'AUTHD_LOCAL_PORT'} || undef;
my $ipRemote = $ENV{'AUTHD_REMOTE_IP'} || undef;
my $enc = $ENV{'AUTHD_ENCRYPTED'} || undef;

my $errMsg = "Died. This script must be executed from pure-ftpd.\n";
die ($errMsg) unless $login;
die ($errMsg) unless $passwd;
die ($errMsg) unless $ipLocal;
die ($errMsg) unless $portLocal;
die ($errMsg) unless $ipRemote;
#die ($errMsg) unless $enc; # enc seems to be unused;

my $mesg;
my $uid;
my $gid;
my $dir;
my @groups;

my $ldapConn = Net::LDAP->new($ldapHost, port => $ldapPort,
	version => $ldapVersion);
if (!$ldapConn) {
	&authFail;
}

if ($ldapTLS == 1) {
	$mesg = $ldapConn->start_tls();
	if ($mesg->is_error) {
		$ldapConn->disconnect;
		&authFail;
	}
}

if (!$ldapBindDN) {
	# bind straight
	my $bindDN = "uid=%s,ou=people,".$ldapBaseDN;
	$bindDN = sprintf($bindDN, $login);
	$mesg = $ldapConn->bind($bindDN, password=> $passwd);
	if ($mesg->is_error) {
		$ldapConn->disconnect;
		&authFail;
	}
	# search for myself (?)
	my $filter = "(objectClass=*)";
	my $search = $ldapConn->search(
		base => $bindDN,
		scope => 'sub',
		filter => $filter,
		attrs => ['uidNumber', 'gidNumber', 'homeDirectory'],
		);
	if (($search->count != 1) || $search->is_error) {
		$ldapConn->disconnect;
		&authFail;
	}
	
	my $entry = $search->entry(0);
	# get uid, gid and dir
	$uid = $entry->get_value('uidNumber');
	$gid = $entry->get_value('gidNumber');
	$dir = $entry->get_value('homeDirectory');
	if (!$uid || !$gid || !$dir) {
		$ldapConn->disconnect;
		&authFail;
	}

	# everything beyond this point is esential
	# get other groups, if there are any
	my $searchBase = $ldapBaseDN;
	if (defined $ldapGidBaseDN) {
		$searchBase = sprintf("%s,%s", $ldapGidBaseDN, $ldapBaseDN);
	}
	$filter = sprintf($ldapGidFilter, $login);
	printf("%s\n", $searchBase);
	printf("%s\n", $filter);
	$search = $ldapConn->search(
		base => $searchBase,
		scope => 'sub',
		filter => $filter,
		attrs => ['gidNumber'],
		);
	if ($search->count > 0 && !$search->is_error) {
		while ($entry = $search->shift_entry()) {
			my $val = $entry->get_value('gidNumber');
			if ($val) {
				push(@groups, $val);
			}
		}
	}
} else {
	# bind via proxy user
	$mesg = $ldapConn->bind($ldapBindDN, password => $ldapPasswd);
	if ($mesg->is_error) {
		$ldapConn->disconnect;
		&authFail;
	}

	# search for dn && bind
	my $filter = sprintf($ldapUidFilter, $login);
	my $searchBase = $ldapBaseDN; 
	if (defined $ldapUidBaseDN) {
		$searchBase = sprintf("%s,%s", $ldapUidBaseDN, $ldapBaseDN);
	}
	my $search = $ldapConn->search(
		base => $searchBase,
		scope => 'sub',
		filter => $filter,
		attrs => ['uidNumber', 'gidNumber', 'homeDirectory'],
		);
	if (($search->count != 1) || $search->is_error) {
		$ldapConn->disconnect;
		&authFail;
	}
	
	my $entry = $search->entry(0);
	$mesg = $ldapConn->bind($entry->dn, password => $passwd);
	if ($mesg->is_error) {
		$ldapConn->disconnect;
		&authFail;
	}
	# get uid, gid and dir
	$uid = $entry->get_value('uidNumber');
	$gid = $entry->get_value('gidNumber');
	$dir = $entry->get_value('homeDirectory');
	if (!$uid || !$gid || !$dir) {
		$ldapConn->disconnect;
		&authFail;
	}

	# everything beyond this point is esential
	# get other groups, if there are any
	$searchBase = $ldapBaseDN;
	if (defined $ldapGidBaseDN) {
		$searchBase = sprintf("%s,%s", $ldapGidBaseDN, $ldapBaseDN);
	}
	$filter = sprintf($ldapGidFilter, $login);
	printf("%s\n", $searchBase);
	printf("%s\n", $filter);
	$search = $ldapConn->search(
		base => $searchBase,
		scope => 'sub',
		filter => $filter,
		attrs => ['gidNumber'],
		);
	if ($search->count > 0 && !$search->is_error) {
		while ($entry = $search->shift_entry()) {
			my $val = $entry->get_value('gidNumber');
			if ($val) {
				push(@groups, $val);
			}
		}
	}
}
$ldapConn->disconnect;

my $groupsFound = 0;
my $groupsRequired = @reqLdapGroups;
for my $group (@groups) {
	for my $groupLdap (@reqLdapGroups) {
		$groupsFound+= 1 if ($group eq $groupLdap);
	}
} # for $group

&authFail if ($groupsFound != $groupsRequired);

&authOk($uid, $gid, $dir, @groups);
