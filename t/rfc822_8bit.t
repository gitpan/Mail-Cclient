use Mail::Cclient qw(rfc822_8bit);

print "1..2\n";

print "ok 1\n";

rfc822_8bit("Orquídea") or print "not ";

print "ok 2\n";
