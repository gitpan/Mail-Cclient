#!/usr/bin/perl

use Mail::Cclient qw(set_callback rfc822_base64);

my $pwd = `pwd`;
chomp($pwd);
$pwd =~ s/\/examples//;

my $mailbox = "$pwd/testmbx/multipart.mbox";

set_callback(
	log => sub {
		my ($str, $type) = @_;
		print "$type: $str\n";
	},
	dlog => sub { print "debug: $_[0]\n" }
);

my $c = Mail::Cclient->new($mailbox, 'readonly');
# MIME section specifier (#.#.#...# = 3)
my $body = $c->fetch_body(1, "3", "uid") or die("Error: $!");
&decode_body_in_place("BASE64", $body);

my $filedest = "image.gif";
open(FILE, ">$filedest") or die("can't open $filedest: $!");
print FILE $body;
close(FILE);

exit();

sub decode_body_in_place {
	my $encoding = lc(shift);

	($encoding and defined($_[0]) and length($_[0])) or return();
	for($_[0]) {
		if($encoding eq "base64") {
			$_ = rfc822_base64($_);
		} elsif($encoding eq "quoted-printable") {
			s/[ \t]*\r?$//mg;
			s/=\n//sg;
			s/=([0-9a-fA-F]{2})/chr(hex($1))/ge;
		}
	}
}
