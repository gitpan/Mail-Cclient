use Mail::Cclient;

print "1..5\n";

print "ok 1\n";

my $pwd = `pwd`;
chomp($pwd);
my $mailbox = "$pwd/testmbx/test.mbox";

my $c = Mail::Cclient->new($mailbox, 'readonly') or print "not ";

print "ok 2\n";

my $uid = $c->uid(1) or print "not ";

print "ok 3\n";

$c->msgno($uid) or print "not ";

print "ok 4\n";

$c->close();

print "ok 5\n";

undef($c);
