use Mail::Cclient qw(set_callback);

print "1..5\n";

print "ok 1\n";

set_callback(
	log => sub {
		my ($str, $type) = @_;
		print "$type: $str\n";
	},
);

print "ok 2\n";

my $pwd = `pwd`;
chomp($pwd); 
my $mailbox = "$pwd/testmbx/test.mbox";

my $c = Mail::Cclient->new($mailbox, 'readonly') or print "not ";

print "ok 3\n";

$c->check;

print "ok 4\n";

$c->close();

print "ok 5\n";

undef($c);
