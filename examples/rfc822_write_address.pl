#!/usr/bin/perl

use Mail::Cclient qw(rfc822_write_address);

my $mailbox = "hdias";
my $host = "xyz.org";
my $personal = "Henrique Dias";

my $str = rfc822_write_address($mailbox, $host, $personal);

print "$str\n";

exit();
