use ExtUtils::MakeMaker;
use Getopt::Long();
use vars qw($opt);

my ($CCLIENT_DIR, $PAMLIBS, $SSLLIBS);

my $opt = {};
Getopt::Long::GetOptions($opt,
	"help"          => \&usage,
	"cclient_dir=s" => \$CCLIENT_DIR,
	"with-pam"      => sub { $PAMLIBS = " -lpam -lpam_misc"; },
	"with-ssl"      => sub { $SSLLIBS = " -lcrypto -lssl"; },
) or die <<EOUSAGE;
usage: $0

  --cclient_dir=/path/to/c-client
  --with-pam
  --with-ssl
  --help

EOUSAGE

die "Missing cclient_dir: --cclient_dir=<dir>\n"
	unless($CCLIENT_DIR);

die "CCLIENT_DIR $CCLIENT_DIR does not contain c-client.a\n"
	if(!-r "$CCLIENT_DIR/c-client.a");

$LIBS = "-lc";
if($PAMLIBS) {
	print "configure with pam:$PAMLIBS\n";
	$LIBS .= $PAMLIBS;
}
if($SSLLIBS) {
	print "configure with ssl:$SSLLIBS\n";
	$LIBS .= $SSLLIBS;
}

#
# We want to turn Cclient.o (ours) plus the object files in the
# $CCLIENT_DIR/c-client.a archive into a shared object. Simply
# including both in the MakeMaker OBJECT list works fine for Linux
# but under Digital UNIX, the combination of its ar and "ld -shared"
# can't cope with simply "ar cr tmp.a Cclient.o .../c-client.a".
# To get around that look at the contents of the c-client.a archive
# and extract all .o files from it into the current directory. Then
# we set OBJECT to be our Cclient.o plus all of those. Blech.
#

my @contents = ();
print "Examining archive file $CCLIENT_DIR/c-client.a...\n";   
chomp(@contents = `ar t $CCLIENT_DIR/c-client.a`);
my @objects = grep(/\.o$/, @contents);
print "Extracting object files from archive: ", join(", ", @objects), "\n";
system("ar", "x", "$CCLIENT_DIR/c-client.a", @objects);

my $err = $? >> 8;
if ($err) {
	print <<END_OF_TEXT;
Extraction failed: ar returned exit code $err
Please extract them manually into the current directory
edit Makefile.PL to remove this section of code and then rerun
    perl Makefile.PL
END_OF_TEXT
	exit(1);
}
print "Extraction was apparently successful\n";

WriteMakefile(
	NAME         => "Mail::Cclient",
	VERSION_FROM => "Cclient.pm",
	INC          => "-I$CCLIENT_DIR",
	LIBS         => [$LIBS],
	OBJECT       => "criteria.o Cclient.o @objects"
);

exit(0);

sub usage {
	print STDERR <<"USAGE";
Usage: perl $0 [options]

Possible options are:

  --cclient_dir=<dir>    Where <dir> is the pathname of the directory
                         which contains the c-client.a archive library
                         which you have just built.

  --with-pam             Configure with support for PAM

  --with-ssl             Configure with support for SSL

  --help                 Print this message and exit

USAGE
  exit 1;
}
