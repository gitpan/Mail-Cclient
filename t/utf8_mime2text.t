use Mail::Cclient qw(utf8_mime2text);

print "1..2\n";

print "ok 1\n";

utf8_mime2text('=?utf-8?B?QW5kculh?= <andreamonteiro@bol.com.br>')
	or print "not ";

print "ok 2\n";
