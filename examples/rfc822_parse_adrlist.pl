#!/usr/bin/perl

use Mail::Cclient qw(rfc822_parse_adrlist);

my $addr = "Henrique Dias <hdias\@xyz.org>, postmaster\@xyz.org, root", "xyz.org";
my $list = rfc822_parse_adrlist($addr, "xyz.org");

for(@{$list}) {
	print "Personal:" . $_->personal . "\n";
	print "     Adl:" . $_->adl . "\n";
	print " Mailbox:" . $_->mailbox . "\n";
	print "    Host:" . $_->host . "\n";
	print "   Error:" . $_->error . "\n";
}
exit();
