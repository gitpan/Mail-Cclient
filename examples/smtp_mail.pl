#!/usr/bin/perl

use Mail::Cclient;

my $smtp = Mail::Cclient::SMTP->new(
	hostlist => ["smtp1.perl.org", "smtp2.perl.org"],
	service  => "smtp",
	port     => 25
);

$smtp->mail(
	transaction => "mail",
	defaulthost => "smtp1.perl.org",
	envelope => {
		from        => "hdias\@perl.org",
		to          => "hdias\@aesbuc.pt",
		subject     => "this is a test",
	},
	body => {
		content_type => "text/plain",
		language     => ["en", "pt"],
		location     => "http://search.cpan.org/CPAN/authors/id/H/HD/HDIAS/Mail-Cclient-1.12.tar.gz",
		md5          => "7YtYbnB1w9PvjMd4qbUkcg==",
		id           => "<8CBACA69-45C3-49C8-B182-D6A99CD9B40D>",
		encoding     => "quoted-printable",
		data         => "This is the data...",
	}
);

$smtp->close();
exit(0);
