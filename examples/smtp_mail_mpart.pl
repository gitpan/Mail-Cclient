#!/usr/bin/perl

use Mail::Cclient;

my $smtp = Mail::Cclient::SMTP->new(["smtp1.perl.org","smtp2.perl.org"]);

$smtp->mail(
	transaction => "mail",
	defaulthost => "perl.org",
	envelope => {
		from        => "hdias\@perl.org",
		to          => "mallocom\@perl.org",
		cc	    => "",
		subject     => "this is a test",
		return_path => "",
	},
	body => {
			content_type => "multipart/mixed",
			part         => [{
				content_type => "image/jpeg",
				encoding     => "binary",
				disposition  => {
					type      => "attachment",
					parameter => [{
							attribute => "filename",
							value     => "test.jpg",
						},
						{
							attribute => "autor",
							value     => "Henrique",
						}
						],
				},
				parameter => [
						{
							attribute => "name",
							value     => "test.jpg",
						}
					],
				description => "Eu sou a descricao!",
				path => "/home/users/hdias/test.jpg",
			},
			{
				content_type => "text/plain",
				encoding     => "quoted-printable",
				data         => "This is the data...",
			},
		],
	}
);

$smtp->close();

exit(0);
