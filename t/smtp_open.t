use Mail::Cclient;

print "1..3\n";

print "ok 1\n";

my $smtp = Mail::Cclient::SMTP->new(
	hostlist => "rosa.esb.ucp.pt",
	service  => "smtp",
	options  => "dsn",
);

print "ok 2\n";

$smtp->close();

print "ok 3\n";

undef($smtp);
