use Mail::Cclient;

print "1..4\n";

print "ok 1\n";

my $pwd = `pwd`;
chomp($pwd); 
my $mailbox = "$pwd/testmbx/test.mbox";

my $c = Mail::Cclient->new($mailbox, 'readonly') or print "not ";

print "ok 2\n";

my ($env, $body) = $c->fetch_structure(1);

print "not " unless($env || $body);

print "ok 3\n";

$c->close();

print "ok 4\n";

undef($c);
