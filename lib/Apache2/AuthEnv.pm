package Apache2::AuthEnv;

=head1 NAME

Apache2::AuthEnv - Perl Authentication and Authorisation via Environment Variables.

=head1 SYNOPSIS

 ### In httpd.conf file (required to load the directives).
 PerlOptions +GlobalRequest
 PerlModule Apache2::AuthEnv

 ### In httpd.conf or .htaccess: ################
 # Set the remote user and trigger the auth* stages
 AuthEnvVar %{REMOTE_ADDR}@%{SOME_ENV_VAR}

 # Set extra environment variables.
 AuthEnvSet	HTTP_AE_SERVER	%{SERVER_ADDR}:%{SERVER_PORT}

 # Allow and Deny access based on environment.
 # The default is to deny access.
 # Allow and deny rules are evaluated based on their order in this file.
 AuthEnvAllowUser	fred@here.org
 AuthEnvDenyUser	george@here.org
 AuthEnvAllowMatch	%{HTTP_USER_AGENT}	^Mozilla
 AuthEnvDeny		%{REMOTE_ADDR}		192.168.2.3
 AuthEnvDenyMatch	%{HTTP_USER_AGENT}	Fedora
 AuthEnvAllow		%{SERVER_PORT} 80

 AuthEnvDenial		UNAUTHORISED|UNAUTHORIZED|NOT_FOUND|FORBIDDEN

=head1 DESCRIPTION

B<Apache2::AuthEnv> allows you to promote a string composed of CGI
environment variables to act as an authenticated user. The format is
set via the AuthEnvVar command and the result is placed in the
environment variable B<REMOTE_USER>.

This module is for use only when another Apache module pre-authenticates
and pre-authorises a user but does not provide authentication nor
authorisation controls within Apache.

This module, once loaded, is triggered by the Apache directive
I<AuthEnvVar> setting a format from the environment for the remote
user name. Authorisation is controlled by I<AuthEnvAllow*> and
I<AuthEnvDeny*> directives. The default is to deny authorisation
to everyone.

  AuthEnvVar		%{HTTP_SSO_USER}@%{HTTP_SSO_ORG}
  AuthEnvAllowUser	fred@ORG

Such a system is Computer Asscoiates' SiteMinder (c) Single Sign On
solution. Only pre-authenticated and pre-authorised users are allowed
through to protected URLs. However there is no local control by the
local web server. SiteMinder sets various environment variables
including HTTP_SM_USER and HTTP_SM_AUTHDIRNAME. So a reasonable
setting would be

  AuthEnvVar		%{HTTP_SM_USER}@%{HTTP_SM_AUTHDIRNAME}
  AuthEnvAllowUser	fred@ORG

Another example is
  AuthEnvVar		%{HTTP_UI_PRINCIPAL_NAME}
  AuthEnvAllowUser	fred@ORG.org
  AuthEnvAllow		%{HTTP_UI_DEPARTMENT} sales

For nested directives, configurations are inherited from one
configuration file to the next. I<AuthEnvVar> directives overwrite each
other as do collections of I<AuthEnvAllow*> rules. Each individual
AuthEnvSet, unless overwriten, is inherited.

The default denial code returned to the browser is FORBIDDEN.
The directive I<AuthEnvDenial> can be used to change the return code.
For example,

  AuthEnvDenial		NOT_FOUND

=head1 METHODS

=over 4

=item * handler()

This is the method used as augument to the I<PerlAuthenHandler> or the
I<PerlAuthzHandler> directives in .htaccess and httpd.conf files.

=item * authenticate()

This is the method used as augument to the the PerlAuthenHandler
directive in .htaccess and httpd.conf files.

=item * authorise()

This is the method used as augument to the the PerlAuthzHandler
directive in .htaccess and httpd.conf files.

=head1 APACHE DIRECTIVES

In the Apache configuration file httpd.conf, the module must be loaded

=over 4

PerlOptions +GlobalRequest

PerlModule Apache2::AuthEnv

=back

=item * AuthEnvVar <format>

This turns on the authentication and authorisation stages and sets the
format for the remote user name, which is filled in during
authentication.

=item * AuthEnvSet <variable> <format>

This sets the specified environment variable using the sepcified format.

=item * AuthEnvAllowUser <user>

=item * AuthEnvDenyUser <user>

These allow or deny the specified user.

=item * AuthEnvAllow <format> <value>

=item * AuthEnvAllowMatch <format> <regex>

=item * AuthEnvDeny <format> <value>

=item * AuthEnvDenyMatch <format> <regex>

These directives allow or deny depending on the environment variables.
Those that end in I<Match> match the environment against a Perl regular
repression and the others require exact matches.

These allow or deny the specified user.

=item * AuthEnvAllowSplit <format> <split> <value>

=item * AuthEnvAllowSplitMatch <format> <split> <regex>

=item * AuthEnvDenySplit <format> <split> <value>

=item * AuthEnvDenySplitMatch <format> <split> <regex>

These directives allow or deny depending on the environment variables.
The formatted string is first split according to the regular expression
I<split> and then each component is considered separately.
Those that end in I<Match> match the environment against a Perl regular
repression and the others require exact matches.

This is useful for environment variables that are really lists
of values delimited with a specific value.

=item * AuthEnvDenial	UNAUTHORISED|UNAUTHORIZED|NOT_FOUND|FORBIDDEN

This directive sets the HTTP denial code returned to the
browser if authorisation fails. The default is FORBIDDEN.

=head1 AUTHOR

Anthony R Fletcher arif@cpan.org

=head1 COPYRIGHT

Copyright (c) 2008 Anthony R Fletcher. All rights reserved.

This program is free software; you can redistribute it and/or modify it under
the same terms as Perl itself. It is supplied on an-is basis and there
is no warrenty of any kind.

SiteMinder (c) is owned by Computer Asscoiates. This module does not
rely on or use any part of SiteMinder and works purely via the
environemnt within mod_perl.

=head1 SEE ALSO

L<perl(1)>, L<mod_perl(1)>, L<Apache(1)>.

=cut

############################################################
use 5;
use strict;

# allow redefinitions so we can use the reload module.
use warnings FATAL => 'all', NONFATAL => 'redefine';

use vars qw($VERSION);
$VERSION = '1.0';

use Carp;
use Data::Dumper;

use ModPerl::Util;
use Apache2::Module;
use Apache2::Access ();
use Apache2::Log;
use Apache2::CmdParms ();
use Apache2::ServerUtil;
use Apache2::RequestUtil ();
use Apache2::RequestRec;
use Apache2::Const -compile => qw(OK DECLINED NO_ARGS TAKE1 TAKE2 TAKE3
			NOT_FOUND HTTP_FORBIDDEN HTTP_UNAUTHORIZED);

die "The module mod_perl 2.0 is required!" unless
	( exists $ENV{MOD_PERL_API_VERSION} and 
			$ENV{MOD_PERL_API_VERSION} >= 2 ); 


###########################################################
my @directives = (
	{
		name	=> 'AuthEnvVar',
		errmsg	=> 'AuthEnvAllow EnvVarFrormat',
	},
	{
		name		=> 'AuthEnvAllowUser',
		args_how	=> Apache2::Const::TAKE1,
		errmsg		=> 'AuthEnvAllowUser User',
	},
	{
		name		=> 'AuthEnvDenyUser',
		args_how	=> Apache2::Const::TAKE1,
		errmsg		=> 'AuthEnvDenyUser User',
	},
	{
		name		=> 'AuthEnvAllow',
		args_how	=> Apache2::Const::TAKE2,
		errmsg		=> 'AuthEnvAllow EnvVarFormat Value',
	},
	{
		name		=> 'AuthEnvAllowMatch',
		args_how	=> Apache2::Const::TAKE2,
		errmsg		=> 'AuthEnvAllow EnvVarFormat RegEx',
	},
	{
		name		=> 'AuthEnvDeny',
		args_how	=> Apache2::Const::TAKE2,
		errmsg		=> 'AuthEnvDeny EnvVarFormat Value',
	},
	{
		name		=> 'AuthEnvDenyMatch',
		args_how	=> Apache2::Const::TAKE2,
		errmsg		=> 'AuthEnvDeny EnvVarFormat RegEx',
	},
	{
		name		=> 'AuthEnvAllowSplit',
		args_how	=> Apache2::Const::TAKE3,
		errmsg		=> 'AuthEnvAllowSplit EnvVarFormat SplitRegEx Value',
	},
	{
		name		=> 'AuthEnvAllowSplitMatch',
		args_how	=> Apache2::Const::TAKE3,
		errmsg		=> 'AuthEnvAllowSplitMatch EnvVarFormat SplitRegEx RegEx',
	},
	{
		name		=> 'AuthEnvDenySplit',
		args_how	=> Apache2::Const::TAKE3,
		errmsg		=> 'AuthEnvDenySplit EnvVarFormat SplitRegEx Value',
	},
	{
		name		=> 'AuthEnvDenySplitMatch',
		args_how	=> Apache2::Const::TAKE3,
		errmsg		=> 'AuthEnvDenySplitMatch EnvVarFormat SplitRegEx RegEx',
	},
	{
		name		=> 'AuthEnvSet',
		args_how	=> Apache2::Const::TAKE2,
		errmsg		=> 'AuthEnvSet EnvVar Format',
	},
	{
		name		=> 'AuthEnvDenial',
		args_how	=> Apache2::Const::TAKE1,
		errmsg		=> 'AuthEnvDenial <UNAUTHORISED|UNAUTHORIZED|NOT_FOUND|FORBIDDEN>'
	},
	
);

# Register the directives.
Apache2::Module::add(__PACKAGE__, \@directives);

# Debugging only.
sub debug { my $r = shift; $r->server->log_error(@_); }

# Create an object; not used by mod_perl2
sub new
{
        # Create an object.
	my $this = shift;
	my $class = ref($this) || $this;
	my $self = { };
	bless $self, $class;

	$self;
}

# Set the environment variable to use for authentication
# and set the system to authenticate and authorise.
sub AuthEnvVar
{
	my ($cfg, $parms, $fmt, @args) = @_;

	# Force auth* stages to be done by loading the configuration.
	my $r = Apache2::RequestUtil->request();
	$r->add_config([
		"PerlAuthenHandler Apache2::AuthEnv::authenticate",
		"PerlAuthzHandler  Apache2::AuthEnv::authorise",
		"Require valid-user",
		"AuthType AuthEnv",
	]);

	# Check that the format contains something to expand.
	unless ($fmt =~ /%{\w+}/)
	{
		$r->server->log_error("AuthEnvVar format has no expansion! AuthEnv cancelled for ", $r->uri);
		return Apache2::Const::HTTP_FORBIDDEN;
	}

	# Save value for user name format.
	$cfg->{AuthEnvVar} = $fmt;

	# Initialise the authorise rule list.
	$cfg->{authorise} = ();

	1;
}


# The @authorise array contains arrays of four elements:
#	the environment format string,
#	if it's an allow rule (1) or deny (0).
#	if it's an exact (1) or a match rule (0).
#	the string to compare/match it against.

sub AuthEnvAllowUser
{
	my ($cfg, $parms, $user) = @_;
	push @{$cfg->{authorise}}, ['%{REMOTE_USER}', 1, 1, undef, $user];
}

sub AuthEnvDenyUser
{
	my ($cfg, $parms, $user) = @_;
	push @{$cfg->{authorise}}, ['%{REMOTE_USER}', 0, 1, undef, $user];
}

sub AuthEnvAllow
{
	my ($cfg, $parms, $var, $regex) = @_;
	push @{$cfg->{authorise}}, [$var, 1, 1, undef, $regex];
}

sub AuthEnvAllowMatch
{
	my ($cfg, $parms, $var, $regex) = @_;
	push @{$cfg->{authorise}}, [$var, 1, 0, undef, $regex];
}

sub AuthEnvDeny
{
	my ($cfg, $parms, $var, $regex) = @_;
	push @{$cfg->{authorise}}, [$var, 0, 1, undef, $regex];
}

sub AuthEnvDenyMatch
{
	my ($cfg, $parms, $var, $regex) = @_;
	push @{$cfg->{authorise}}, [$var, 0, 0, undef, $regex];
}

sub AuthEnvAllowSplit
{
	my ($cfg, $parms, $var, $split, $regex) = @_;
	push @{$cfg->{authorise}}, [$var, 1, 1, $split, $regex];
}

sub AuthEnvAllowSplitMatch
{
	my ($cfg, $parms, $var, $split, $regex) = @_;
	push @{$cfg->{authorise}}, [$var, 1, 0, $split, $regex];
}

sub AuthEnvDenySplit
{
	my ($cfg, $parms, $var, $split, $regex) = @_;
	push @{$cfg->{authorise}}, [$var, 0, 1, $split, $regex];
}

sub AuthEnvDenySplitMatch
{
	my ($cfg, $parms, $var, $split, $regex) = @_;
	push @{$cfg->{authorise}}, [$var, 0, 0, $split, $regex];
}

sub AuthEnvSet
{
	my ($cfg, $parms, $var, $fmt) = @_;

	push @{$cfg->{set}}, [$var, $fmt];
}

sub AuthEnvDenial
{
	my ($cfg, $parms, $code) = @_;

	if ($code =~ /FORBIDDEN/i)
	{
		$cfg->{Denial} = Apache2::Const::HTTP_FORBIDDEN;
	}
	elsif ($code =~ /UNAUTHORI[SZ]ED/i)
	{
		$cfg->{Denial} = Apache2::Const::HTTP_UNAUTHORIZED;
	}
	elsif ($code =~ /NOT.FOUND/i)
	{
		$cfg->{Denial} = Apache2::Const::NOT_FOUND;
	}
	else
	{
		my $r = Apache2::RequestUtil->request();

		# warning to correct error log
		$r->server->log_error("Invalid argument '$code' to AuthEnvDenial in ", $parms->path);

		# Set a default.
		$cfg->{Denial} = Apache2::Const::HTTP_FORBIDDEN;

		return 0;
	}

	1;
}

# Merge configuration objects together so the the various 
# Apache config files override each other.
sub merge
{
        my ($base, $add) = @_;

	my $merged = new Apache2::AuthEnv;

	# Merge environment variables to set.
	$merged->{set} = $base->{set};
	push @{$merged->{set}}, @{$add->{set}};
	delete $base->{set};
	delete $add->{set};

	for my $k (keys %$base) { $merged->{$k} = $base->{$k}; } 
	for my $k (keys %$add)  { $merged->{$k} = $add->{$k};  }

	$merged;
}

# Turn on custom merging.
sub DIR_MERGE    { merge(@_) }
sub SERVER_MERGE { merge(@_) }


###########################################################

# NB There is almost no environment to speak of at this time!

# Authenticate a user based on the presence of environemnt variables.
# Fail to authenticate if a environment variable doesn't exist.
# Promote environment variables in format to REMOTE_USER.
sub authenticate
{
	my ($r) = @_;

	# recover configuration.
        my $cfg = Apache2::Module::get_config(__PACKAGE__, $r->server, $r->per_dir_config);

	# Check that we are using the right AuthType directive.
	my $type = __PACKAGE__; $type =~ s/^.*:://;
	if ($r->auth_type ne $type)
	{
		$r->server->log_error("Wrong authentication Type ", $r->auth_type);
		return Apache2::Const::HTTP_UNAUTHORIZED;
	}
	unless (defined $cfg->{AuthEnvVar})
	{
		$r->server->log_error("AuthEnvVar not used! ", $r->auth_type);
		return Apache2::Const::HTTP_UNAUTHORIZED;
	}

	# Set AuthEnvVar value. Depreciated!
	#my $AuthEnvVar = $r->dir_config('AuthEnvVar') || $cfg->{AuthEnvVar};

	# Import CGI environment.
	$r->subprocess_env unless $r->is_perl_option_enabled('SetupEnv');

        # expand $AuthEnvVar format; fail if a variable doesn't
        # not exist.
	my $user = $cfg->{AuthEnvVar};
	my $fail = 0; # count non-existant variables.
	$user =~ s/%{(\w+)}/(defined($r->subprocess_env($1)) ? $r->subprocess_env($1) : $fail++)/gxe;

	# Failure.
	return Apache2::Const::HTTP_UNAUTHORIZED if $fail;
	return Apache2::Const::HTTP_UNAUTHORIZED unless defined $user;
	return Apache2::Const::HTTP_UNAUTHORIZED if ($user eq '');

	# Success! User authenticated

	# Set REMOTE_USER, etc..
	$r->subprocess_env('REMOTE_USER', $user);
	$r->user($user);

	# Set the environment.
	$r->subprocess_env('HTTP_AE_VERSION', $VERSION);
	for my $s (@{$cfg->{set}})
	{
		my ($v, $f) = @$s;
		$f =~ s/%{(\w+)}/$r->subprocess_env($1)/gxe;
		$r->subprocess_env($v, $f);
	}

	# succeed.
	return Apache2::Const::OK;
}

# Match the various allow or deny rules.
sub allowed
{
	my ($r, @list) = @_;

	#debug $r, 1+$#list, " authorise rules\n";

	for my $a (@list)
	{
		# Each rule consists of 3 parts.
		my ($val, $allow, $exact, $split, $regex) = @{$a};

		my $fail = 0; # count non-existant variables.

		# Substitute.
		$val =~ s/%{(\w+)}/(defined($r->subprocess_env($1)) ? $r->subprocess_env($1) : $fail++)/gxe;

		# Fail if this contains a non-existant environment variable.
		return 0 if $fail;

		#debug $r, "$val $exact $regex\n";

		# Split the value up if required.
		my @parts = (defined $split) ? split(/$split/, $val) : $val;

		#warn "parts = ", join('-', @parts);

		# Check each part.
		for my $v (@parts)
		{
			#warn "checking '$v' with '$regex' (exact=$exact)\n";
			my $match = $exact
				? ($v eq $regex)
				: ($v =~ m/$regex/);


			return $allow if $match;
		}
	}

	0;
}

# Look through the deny and allow rules; fail by default.
sub authorise
{
	my ($r) = @_;

	# recover configuration.
        my $cfg = Apache2::Module::get_config(__PACKAGE__, $r->server, $r->per_dir_config);

	#debug $r, "$#authorise authorise rules\n";

	# default denial code.
	$cfg->{Denial} ||= Apache2::Const::HTTP_FORBIDDEN;

	# Import CGI environment.
	$r->subprocess_env unless $r->is_perl_option_enabled('SetupEnv');

	# Sanity check that there is a authenticated user.
	my $user = $r->user;
	unless ($user)
	{
		$r->server->log_error("No authenticated user ", $r->uri);
		return $cfg->{Denial};
	} 

	# Check allow rules.
	allowed($r, @{$cfg->{authorise}}) && 
		return Apache2::Const::OK;

	# Fail by default.
	$r->server->log_error("User $user denied ", $r->uri);

	return $cfg->{Denial};

	return Apache2::Const::NOT_FOUND;
	return Apache2::Const::HTTP_FORBIDDEN;
	return Apache2::Const::HTTP_UNAUTHORIZED;
}

# Default handler
sub handler
{ 
	my ($r) = @_;

	# What phase are we in?
	my $phase = ModPerl::Util::current_callback();

	# Handle the right phase in the right way.
	if ($phase eq 'PerlAuthenHandler') { return authenticate(@_); }
	if ($phase eq 'PerlAuthzHandler')  { return authorise(@_); }

	# This phase is not handled by this module.
	$r->server->log_error("Handler called in wrong phase ($phase)!");

	return Apache2::Const::HTTP_FORBIDDEN;
}

# Alternative spelling.
sub authorize { authorise(@_); }

1;


