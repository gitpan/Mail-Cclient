use Mail::Cclient;

print "1..4\n";

print "ok 1\n";

my $pwd = `pwd`;
chomp($pwd); 
my $mailbox = "$pwd/testmbx/test_mpart.mbox";

my $c = Mail::Cclient->new($mailbox, 'readonly') or print "not ";

print "ok 2\n";

$c->fetch_mime(1, "2") or print "not ";

print "ok 3\n";

$c->close();

print "ok 4\n";

undef($c);
