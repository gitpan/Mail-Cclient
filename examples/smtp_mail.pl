#!/usr/bin/perl

use Mail::Cclient;

my $smtp = Mail::Cclient::SMTP->new(
	hostlist => ["smtp1.perl.org", "smtp2.perl.org"],
	service  => "smtp",
	port     => 25
);

$smtp->mail(
	transaction => "mail",
	defaulthost => "rosa.esb.ucp.pt",
	envelope => {
		from        => "hdias\@perl.org",
		to          => "hdias\@aesbuc.pt",
		subject     => "this is a test",
	},
	body => {
		content_type => "text/plain",
		encoding     => "quoted-printable",
		data         => "This is the data...",
	}
);

$smtp->close();
exit(0);
