# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
# Last Modification: Wed Oct  6 13:30:32 WEST 2004
use ExtUtils::MakeMaker;
use Getopt::Long();
use vars qw($opt);

my ($CCLIENTLIBS, $CCLIENT_DIR, $PAM_DIR, $SSL_DIR, $KRB_DIR, $IMAP_DIR);
my @objects = ();

my $opt = {};
Getopt::Long::GetOptions($opt,
	"help"                    => \&usage,
	"cclient_dir=s"           => \$CCLIENT_DIR,
	"with-shared_cclient"     => sub { $CCLIENTLIBS = " -lc-client"; },
	"with-pam:s"              => \$PAM_DIR,
	"with-ssl:s"              => \$SSL_DIR,
	"with-kerberos:s"         => \$KRB_DIR,
	"with-cclient-includes=s" => \$IMAP_DIR,
) or die <<EOUSAGE;
usage: $0

  --cclient_dir=/path/to/c-client
  --with-shared_cclient
  --with-pam=/path/to/libs (path optional)
  --with-ssl=/path/to/libs (path optional)
  --with-kerberos=/path/to/libs (path optional)
  --with-cclient-includes=/path/to/imap_includes
  --help

EOUSAGE

unless($CCLIENTLIBS) {
	die "Missing cclient_dir: --cclient_dir=<dir> [--help]\n"
		unless($CCLIENT_DIR);
	die "CCLIENT_DIR $CCLIENT_DIR does not contain c-client.a\n"
		if(!-r "$CCLIENT_DIR/c-client.a");
}

my %headers = ();
my $osname = lc($^O);
my @libs = "-lc";
push(@libs, "-lm") if($osname eq "aix");
$LIBS = join(" ", @libs);

if($CCLIENTLIBS) {
	print "configure with shared c-client:$CCLIENTLIBS\n";
	$LIBS .= $CCLIENTLIBS;
	if($IMAP_DIR) {
		$CCLIENT_DIR = $IMAP_DIR;
		$headers{'HAVE_IMAP_LINKAGE'} = 1 if(-e "$IMAP_DIR/linkage.c");
	}
}
if(defined($PAM_DIR)) {
	my $tmp = " -L$PAM_DIR" if($PAM_DIR);
	$tmp .= " -lpam -lpam_misc";
	print "configure with pam:$tmp\n";
	$LIBS .= $tmp;
}
if(defined($SSL_DIR)) {
	my $tmp = " -L$SSL_DIR" if($SSL_DIR);
	$tmp .= " -lcrypto -lssl";
	print "configure with ssl:$tmp\n";
	$LIBS .= $tmp;
	$headers{'HAVE_IMAP_SSL'} = 1;
}

if(defined($KRB_DIR)) {
	my $tmp = " -L$KRB_DIR" if($KRB_DIR);
	$tmp .= " -lgssapi_krb5 -lkrb5 -lk5crypto -lcom_err";
	print "configure with kerberos:$tmp\n";
	$LIBS .= $tmp;
}

unlink("Cclient.h") if(-e "Cclient.h");
open(HEADERS, ">", "Cclient.h") or die("$!");
while(my ($key, $value) = each(%headers)) {
	print HEADERS "#define $key $value\n";
}
close(HEADERS);

unless($CCLIENTLIBS) {
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
	@objects = grep(/\.o$/, @contents);
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
}
unshift(@objects, "criteria.o", "Cclient.o");

WriteMakefile(
	NAME         => "Mail::Cclient",
	VERSION_FROM => "Cclient.pm",
	INC          => "-I$CCLIENT_DIR",
	LIBS         => ["$LIBS"],
	OBJECT       => "@objects"
);

exit(0);

sub usage {
	print STDERR <<"USAGE";
Usage: perl $0 [options]

Possible options are:

  --cclient_dir=<dir>           Where <dir> is the pathname of the
                                directory which contains the c-client.a
                                archive library which you have just built.

  --with-shared_cclient         Configure with support for a shared
                                c-client library

  --with-pam=<dir>              Configure with support for PAM.
                                Where <dir> is the pathname of the
                                directory which contains the libs.
                                <dir> is optional.

  --with-ssl=<dir>              Configure with support for SSL
                                Where <dir> is the pathname of the
                                directory which contains the libs.
                                <dir> is optional.

  --with-kerberos=<dir>         Configure with support for Kerberos
                                Where <dir> is the pathname of the
                                directory which contains the libs.
                                <dir> is optional.

  --with-cclient-includes=<dir> Where the c-client header files live

  --help                        Print this message and exit

USAGE
  exit 1;
}
