#!/usr/bin/perl

use Mail::Cclient qw(set_callback);

my $pwd = `pwd`;
chomp($pwd);
$pwd =~ s/\/examples//;

my $mailbox = "$pwd/testmbx/multipart.mbox";

set_callback(
	log => sub {
		my ($str, $type) = @_;
		print "$type: $str\n";
	},
	dlog => sub { print "debug: $_[0]\n" }
);

my $c = Mail::Cclient->new($mailbox, 'readonly');
my ($env, $body) = $c->fetch_structure(1, "uid") or die("$!");

print "   From: ", addr($env->from), "\n",
print "     To: ", addr($env->to), "\n";
print "Subject: ", $env->subject, "\n";
print "\n";

my $parts = &init_structure($body);
for my $k (sort(keys(%{$parts}))) {
	print "Part ($k)\n";
	print "   Filename: ", $parts->{$k}->{'filename'}, "\n";
	print "       Size: ", $parts->{$k}->{'size'}, "\n";
	print "   Encoding: ", $parts->{$k}->{'encoding'}, "\n";
	print "  Mime Type: ", $parts->{$k}->{'mime_type'}, "\n";
	print "Disposition: ", $parts->{$k}->{'disposition'}, "\n";
	print "Description: ", $parts->{$k}->{'description'}, "\n";
	print "  Parameter: ", $parts->{$k}->{'parameter'}, "\n";
	print "\n";
}
$c->close();

exit();

sub addr {
	my $alist = shift;
	return join(", ",
		map { sprintf('%s@%s (%s)',
			$_->mailbox, $_->host, $_->personal)
		} @$alist);
}

sub init_structure {
	my $body = shift;
	my %hash = ();
	&output_structure(\%hash, "", $body);
	return(\%hash);
}

sub output_structure {
	my $hash = shift;
	my $id = shift;
	my $body = shift;

	my $type = lc($body->type);
	if($type eq "multipart") {
		$id = join("\.", $id, "") if($id);
		my $nested = $body->nested;
		my $count = scalar(@{$nested});
		for(my $i = 1; $i <= $count; $i++) { &output_structure($hash, "$id$i", $nested->[$i - 1]); }
	} else {
		$id = "1" unless($id);
		my ($filename, $disposition) = ("", "");
		my ($array, $description) = ($body->disposition, $body->description);
		for my $i (0 .. $#{@$array}) {
			$disposition =  $array->[$i] if(lc($array->[$i]) eq "attachment" || lc($array->[$i]) eq "inline");
			$filename = $array->[$i+1] if(lc($array->[$i]) eq "filename");
		}
		unless($filename) {
			my %p = @{$body->parameter};
			$filename = $p{'NAME'} if(exists($p{'NAME'}));
		}
		$hash->{$id} = {
			size        => $body->bytes,
			mime_type   => join("/", $type, lc($body->subtype)),
			disposition => $disposition,
			description => $description,
			filename    => $filename || $description,
			encoding    => $body->encoding,
			parameters  => $body->parameter, };
		my $parts = $body->nested;
		if($parts->[1]) {
			$id = join("\.", $id, "1") if(lc($parts->[1]->type) ne "multipart");
			&output_structure($hash, $id, $parts->[1]);
		}
	}
}
