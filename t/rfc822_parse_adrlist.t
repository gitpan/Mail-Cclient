use Mail::Cclient qw(rfc822_parse_adrlist);

print "1..2\n";

print "ok 1\n";

rfc822_parse_adrlist("Henrique Dias <hdias\@xyz.org>", "xyz.org")
	or print "not ";

print "ok 2\n";
