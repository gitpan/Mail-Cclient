use Mail::Cclient;

print "1..4\n";

print "ok 1\n";

my $pwd = `pwd`;
chomp($pwd);
my $mailbox = "$pwd/testmbx/test.mbox";

my $c = Mail::Cclient->new($mailbox, 'readonly') or print "not ";

print "ok 2\n";

$c->sort(
	SORT   => ["from", 0, "size", 1, "subject", 0],
	SEARCH => "ALL") or print "not ";

print "ok 3\n";

$c->close();

print "ok 4\n";

undef($c);
