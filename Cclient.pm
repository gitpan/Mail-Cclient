#
#	Cclient.pm
#
#	Copyright (c) 1998,1999,2000,2001 Malcolm Beattie
#
#	You may distribute under the terms of either the GNU General Public
#	License or the Artistic License, as specified in the README file.
# 

package Mail::Cclient;
use DynaLoader;
use Exporter;
use strict;
use vars qw($VERSION @ISA @EXPORT_OK %_callback);

$VERSION = "1.4";
@ISA = qw(Exporter DynaLoader);
@EXPORT_OK = qw(set_callback get_callback rfc822_base64 rfc822_qprint
	rfc822_date rfc822_parse_adrlist rfc822_write_address rfc822_output);

{
	package Mail::Cclient::Address;
	use vars qw(%FIELDS);

	%FIELDS = (
		personal => 1,
		adl      => 2,
		mailbox  => 3,
		host     => 4,
		error    => 5);

	sub personal { shift->[1] }
	sub adl { shift->[2] }
	sub mailbox { shift->[3] }
	sub host { shift->[4] }
	sub error { shift->[5] }
}

{
	package Mail::Cclient::Body;
	use vars qw(%FIELDS);

	%FIELDS = (
		type        => 1,
		encoding    => 2,
		subtype     => 3,
		parameter   => 4,
		id          => 5,
		description => 6,
		nested      => 7,
		lines       => 8,
		bytes       => 9,
		md5         => 10,
		disposition => 11);

	sub type { shift->[1] }
	sub encoding { shift->[2] }
	sub subtype { shift->[3] }
	sub parameter { shift->[4] }
	sub id { shift->[5] }
	sub description { shift->[6] }
	sub nested { shift->[7] }
	sub lines { shift->[8] }
	sub bytes { shift->[9] }
	sub md5 { shift->[10] }
	sub disposition { shift->[11] }
}

{
	package Mail::Cclient::Envelope;
	use vars qw(%FIELDS);

	%FIELDS = (
		remail => 1,
		return_path => 2,
		date        => 3,
		from        => 4,
		sender      => 5,
		reply_to    => 6,
		subject     => 7,
		to          => 8,
		cc          => 9,
		bcc         => 10,
		in_reply_to => 11,
		message_id  => 12,
		newsgroups  => 13,
		followup_to => 14,
		references  => 15);

	sub remail { shift->[1] }
	sub return_path { shift->[2] }
	sub date { shift->[3] }
	sub from { shift->[4] }
	sub sender { shift->[5] }
	sub reply_to { shift->[6] }
	sub subject { shift->[7] }
	sub to { shift->[8] }
	sub cc { shift->[9] }
	sub bcc { shift->[10] }
	sub in_reply_to { shift->[11] }
	sub message_id { shift->[12] }
	sub newsgroups { shift->[13] }
	sub followup_to { shift->[14] }
	sub references { shift->[15] }
}

{
	package Mail::Cclient::Elt;
	use vars qw(%FIELDS);

	%FIELDS = (
		msgno       => 1,
		date        => 2,
		flags       => 3,
		rfc822_size => 4);

	sub msgno { shift->[1] }
	sub date { shift->[2] }
	sub flags { shift->[3] }
	sub rfc822_size { shift->[4] }
}

# Our own methods
sub new {
	my $class = shift;
	return Mail::Cclient::open(undef, @_);
}

sub set_callback {
	while (@_) {
		my $name = shift;
		my $value = shift;
		$_callback{$name} = $value;
	}
}

sub get_callback {
	my $name = shift;
	return $_callback{$name};
}

sub gc {
	my $obj = shift;
	$obj = undef unless ref($obj);
	$obj->real_gc;
}

sub parameters {
	my $stream = shift; # XXX Ignore stream for now
	if (@_ == 1) {
		return _parameters(undef, @_);
	} elsif (@_ % 2) {
		require Carp;
		Carp::croak("Mail::Cclient::parameters takes one argument or pairs");
	}
	while (my ($param, $value) = splice(@_, 0, 2)) {
		_parameters(undef, $param, $value);
	}
	return 1;
}

sub Mail::Cclient::SMTP::new {
	my $class = shift;
	return Mail::Cclient::SMTP::open(undef, @_);
}

bootstrap Mail::Cclient;

1;
