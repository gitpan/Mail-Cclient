#!/usr/bin/perl

use Mail::Cclient;

my $smtp = Mail::Cclient::SMTP->new(["smtp1.perl.org","smtp2.perl.org"]);

$smtp->mail(
	transaction => "mail",
	defaulthost => "perl.org",
	envelope => {
		from        => "hdias\@perl.org",
		to          => "mallcom\@perl.org",
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
