#!/usr/bin/perl

use strict;
use Mail::Cclient qw(set_callback);

unless(scalar(@ARGV) == 3) {
	print STDERR "Usage: ./list_mailboxs.pl host user password\n";
	exit(2);
}
my ($host, $user, $passwd) = @ARGV;
my $ref = "\{$host/imap\}";
my $stream = join("", $ref, "INBOX");
my $pat = join("/", "mail", "%");

set_callback(
	'login' => sub {
		return($user, $passwd);
	},
	'dlog'  => sub {
		print STDERR "debug: $_[0]\n";
	},
	'log'   => sub {
		my ($string, $type) = @_;
		print STDERR "$type: $string\n";
	},
	'list'  => sub {
		shift;
		print "list: @_\n";
	}
);

Mail::Cclient::parameters(undef, RSHTIMEOUT => 0, MAXLOGINTRIALS => 1);
my $cclient = Mail::Cclient->new($stream) or die("Mail::Cclient->new failed\n");
$cclient->list($ref, $pat);
$cclient->close;

exit();
