use Mail::Cclient qw(rfc822_qprint);

print "1..2\n";

print "ok 1\n";

rfc822_qprint("Isto =E9 um teste!!!") or print "not ";

print "ok 2\n";
