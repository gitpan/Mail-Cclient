use Mail::Cclient qw(set_callback);

print "1..6\n";

print "ok 1\n";

my $pwd = `pwd`; 
chomp($pwd);
my $mailbox = "$pwd/testmbx/test.mbox";

my @sequence = ();
set_callback(
	'searched' => sub {
		my ($stream, $number) = @_;
		push(@sequence, $number); } );

print "ok 2\n";

my $c = Mail::Cclient->new($mailbox, 'readonly') or print "not ";

print "ok 3\n";

$c->search(
	SEARCH => "ALL NOT FROM \"hdias\"",
	FLAG   => ["uid"]);

print "ok 4\n";

unless(@sequence) { print "not "; }

print "ok 5\n";

$c->close();

print "ok 6\n";

undef($c);
