use Mail::Cclient qw(rfc822_binary);

print "1..2\n";

print "ok 1\n";

rfc822_binary("Test latin chars: бйнуъгхзвкофы") or print "not ";

print "ok 2\n";
