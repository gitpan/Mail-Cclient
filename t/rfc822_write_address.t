use Mail::Cclient qw(rfc822_write_address);

print "1..2\n";

print "ok 1\n";

rfc822_write_address("hdias", "xyz.org", "Henrique Dias") or print "not ";

print "ok 2\n";
