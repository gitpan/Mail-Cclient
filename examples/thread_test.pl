#!/usr/bin/perl

use Mail::Cclient;
use Data::Dumper;
use strict;

die "Could not find test.mbox to test it!\n"
	unless (-f "../testmbx/test.mbox");

my $result = '$VAR1 = [ [ 1430, 1432 ], [ [ 1, 2, 3 ], [ 4 ] ], [ 104, [ 105 ], [ 106, 111, 121, 139 ], [ 108, 109, 110 ] ], [ 159, [ 160, 162, [ 163, 165 ], [ 164, 166 ] ], [ 161 ] ], [ 204, [ 205 ], [ 208, 209, 210, 212, [ 214, 216, 217, 220 ], [ 215 ] ] ], [ 334, [ 338 ], [ 419 ], [ 472, 476, [ 479, 485, 486 ], [ 492 ] ] ] ];';

print <<EOF;
 
This is the message thread test.
You should get an output like this:

$result

If you don't get it, there is a error in either Mail::Cclient, c-client itself or even this test program: $0.

The tested output is:

EOF
   
my $pwd = `pwd`;
chomp($pwd);
$pwd =~ s/examples$/testmbx/;

my $c = new Mail::Cclient "$pwd/test.mbox" or die "Cannot open mailbox!\n";

my $data = Dumper $c->thread(
				THREADING => "references",
				FLAG      => "uid" );
$data =~ s/\n//g;
$data =~ s/\s+/ /g;

print "$data\n\n";

if($data eq $result) { print "They match.\n"; }
else{ print "Warning! They are not the same!\n"; }
