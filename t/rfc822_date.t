use Mail::Cclient qw(rfc822_date);

print "1..2\n";

print "ok 1\n";

rfc822_date or print "not ";

print "ok 2\n";
