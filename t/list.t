use Mail::Cclient qw(set_callback);

print "1..5\n";

print "ok 1\n";

my $pwd = `pwd`;
chomp($pwd);
my $mailbox = "$pwd/testmbx/test.mbox";

set_callback(
	list => sub {shift; print "list: @_\n";},
);

print "ok 2\n";

my $c = Mail::Cclient->new($mailbox, 'readonly') or print "not ";

print "ok 3\n";

$c->list("", "%");

print "ok 4\n";

$c->close();

print "ok 5\n";

undef($c);
