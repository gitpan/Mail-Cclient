#!/usr/bin/perl -w

use Mail::Cclient qw(utf8_mime2text);

my @mime2 = ('=?utf-8?B?QW5kculh?= <andreamonteiro@bol.com.br>,',
'=?utf-8?B?QW5kcuk=?= <twe20@usa.net>',
'=?utf-8?Q?Eul=E1lia_Vieira_de_Camargo?= <lalinha.mga@zipmail.com.br>,',
'=?utf-8?B?QW5kcuk=?= <twe20@usa.net>',
);

foreach (@mime2){
	print "Original mime2 string: $_\n";
	print "Converted text       : " . utf8_mime2text($_) . "\n";
	print "\n";
}
