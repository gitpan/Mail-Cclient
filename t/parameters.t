use Mail::Cclient;

print "1..3\n";

print "ok 1\n";

Mail::Cclient::parameters(undef,'USERNAME' => "hdias") or print "not ";

print "ok 2\n";

Mail::Cclient::parameters(undef,'USERNAME') or print "not ";

print "ok 3\n";
