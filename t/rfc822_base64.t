use Mail::Cclient qw(rfc822_base64);

print "1..2\n";

print "ok 1\n";

rfc822_base64("This is a teste!") or print "not ";

print "ok 2\n";
