use Mail::Cclient qw(rfc822_base64);

print "1..2\n";

print "ok 1\n";

rfc822_base64("SXN0byDpIHVtIHRlc3RlISEhDQo=") or print "not ";

print "ok 2\n";
