use Mail::Cclient qw(rfc822_qprint);

print "1..2\n";

print "ok 1\n";

rfc822_qprint("This is a teste!") or print "not ";

print "ok 2\n";
