#!/usr/bin/perl
# portscan -h for usage
# created by john tassano

use strict;
use Socket;
use Data::Validate::Domain;
use IO::Socket;
use Win32::Env;


# TCP Port scanner
my $VERSION = '1.0';
$| = 1; # so \r works right, # flush the print buffer

my ($ip, $protocol, $start_port, $end_port, $log, $domain, $address);
$protocol = getprotobyname('tcp');
($ip, $start_port, $end_port, $log) = @ARGV;

print "PORTSCAN v$VERSION\n";


if ($ip eq "-h") {
    &usage();
	exit 0;
}

my $path = $ENV{'USERPROFILE'};
$path =~s/\\/\//g;
$domain = $ip;
$ip = "localhost" if not $ip;
$start_port = 1 if not $start_port;
$end_port = 1024 if not $end_port;
$log = "$path\portscan.txt" if not $log;
my $valid = is_domain($domain);

if ( $valid )
{
	my $resolve = inet_aton($domain);
	$address ="Not valid";
	if ($resolve) {
		$address = inet_ntoa($resolve);
	}
	print "$domain $address \n";
	$ip = $address;
}

if($ip !~  m/^\d+\.\d+\.\d+\.\d+$/)
{
	usage();
	print "Invalid Host\n";
	exit 0;
}

if ( $start_port > $end_port )
{
	usage();
	print "start_port can't be greater then the end_port.\n";
	exit 0;
}


unless (open(LOG_FILE, ">>$log")) {
    die "Can't open log file $log for writing: $!\n"
}

# Make file handle hot so the buffer is flushed after every write
select((select(LOG_FILE), $| = 1)[0]);

print "Checking $ip for open ports $start_port - $end_port\n";

my $ports;
my @open_ports = ();

foreach (my $port = $start_port ; $port <= $end_port ; $port++) 
{
    #\r will refresh the line
    print "\rScanning port $port";
     
    #Connect
    my $socket = IO::Socket::INET->new(PeerAddr => $ip , PeerPort => $port , Proto => 'tcp' , Timeout => 1);
	 
    #Check connection
    if( $socket )
    {
		#use Term::Screen::Uni;
		#my $scr = new Term::Screen::Uni;
		#$scr->clrscr();
		$ports++;
		#push port to array
		push (@open_ports, $port);
        print "\nPort $port is open.\n" ;
		#return if ($port = $end_port);
    }
}
my $datestring = gmtime();
print LOG_FILE "GMT date and time $datestring\n";
#my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime();
#print LOG_FILE "$mon/$mday/$year";
if ($ports) {
	print "\n";
	print "The following ports are open on $ip ";
	print LOG_FILE "The following ports are open on $ip ";
	
	foreach my $data(@open_ports) { 
		print "$data ";
		print LOG_FILE "$data ";
	}
}

print "\n";
print LOG_FILE "\n";
print LOG_FILE "The following ports where tested on $ip between port $start_port and $end_port\n\n";
close LOG_FILE || die "close: $!";

sub usage() {
    print "Usage: portscan [host] [start_port] [end_port] [logfile]\n";
    print "Defaults to localhost and port 1 and port 1024 portscan.txt\n";
}
