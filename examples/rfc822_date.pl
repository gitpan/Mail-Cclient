#!/usr/bin/perl

use Mail::Cclient qw(rfc822_date);

$date = rfc822_date;

print "$date\n";

exit();
