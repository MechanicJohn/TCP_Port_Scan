#!/usr/bin/perl
# portscan -h for usage
# created by john tassano
# John.Tassano@Centurylink.com
# Version 1.3

use strict;
use Socket;
use Data::Validate::Domain;
use IO::Socket;
use Win32::Env;
use Net::Ping;

# TCP Port scanner
my $VERSION = '1.3';
$| = 1; # so \r works right, # flush the print buffer
$SIG{INT} = \&interrupt;
my $LOG_FILE;

my ($ip, $protocol, $start_port, $end_port, $log, $domain, $address, $path);
$protocol = getprotobyname('tcp');
($ip, $start_port, $end_port, $log) = @ARGV;

print "\n";
print " PORTSCAN v$VERSION\n";
print "Debug $ip $start_port $end_port $log"


#my $p = Net::Ping->new;
#if ($p->ping($ip, 1) || $ip == 127.0.0.1 ) {
#    print " Host is reachable\n";
#}
#else{
#	 print " Host is not reachable\n";
#}



if ($ip eq "-h") {
    &usage();
	exit 0;
}

if (!$ip) {
	usage()
}

$path = $ENV{'USERPROFILE'};
$path =~s/\\/\//g;
$domain = $ip;
$ip = "localhost" if not $ip;
$start_port = 1 if not $start_port;
$end_port = 100 if not $end_port;
$log = "$path/portscan.txt" if not $log;
my $valid = is_domain($domain);


if ( $valid )
{
	my $resolve = inet_aton($domain);
	$address ="Not valid";
	if ($resolve) {
		$address = inet_ntoa($resolve);
	}
	print " $domain $address \n";
	$ip = $address;
}

#if($ip !~  m/^\d+\.\d+\.\d+\.\d+$/)
#{
#	usage();
#	print " Invalid Host\n";
#	exit 0;
#}


if($ip !~  m/^\d+\.\d+\.\d+\.\d+$/ and $ip ne "localhost")
{
	usage();
	print " Invalid Host $ip\n";
	exit 0;
}


if ( $start_port > $end_port )
{
	usage();
	print " start_port can't be greater then the end_port. We cant backwards yo.\n";
	exit 0;
}


unless (open($LOG_FILE, ">>$log")) {
    die " Can't open log file $log for writing: $!\n"
}

# Make file handle hot so the buffer is flushed after every write
select((select($LOG_FILE), $| = 1)[0]);

print " Scanning $ip for open ports $start_port - $end_port to log file $log\n";

my $ports;
my @open_ports = ();

print " Press CTRL + C to terminate scan\n";

foreach (my $port = $start_port ; $port <= $end_port ; $port++) 
{
    #\r will refresh the line
    print "\r Scanning TCP port $port";
    #Connect to tcp port
    my $socket = IO::Socket::INET->new(PeerAddr => $ip , PeerPort => $port , Proto => 'tcp' , Timeout => 1);
	 
    #Check tcp connection
    if( $socket )
    {
		$ports++;
		#push port to array
		push (@open_ports, $port);
		$| = 1;
        print "\n Port $port is open.\n" ;
		
    }
}



my $datestring = gmtime();
print " Scan Completed $datestring";
print $LOG_FILE "GMT date and time $datestring\n";
#my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime();
#print LOG_FILE "$mon/$mday/$year";
if ($ports) {
	print "\n";
	print " The following ports are open on $ip port ";
	print $LOG_FILE "The following ports are open on $ip port";
	
	foreach my $data(@open_ports) { 
		print "$data ";
		print $LOG_FILE "$data ";
	}
}

print "\n";
print $LOG_FILE "\n";
print $LOG_FILE "Finished Scanning $ip between port $start_port and $end_port\n\n";
close $LOG_FILE || die "close: $!";
print "\n";
usage();
exit 0;

sub usage() {
    print " Usage: portscan [host] [start_port] [end_port] [logfile]\n";
    print " Defaults: portscan localhost 1 1024 portscan.txt\n";
}

sub interrupt {
	close $LOG_FILE;
	print "\n Terminating PortScan\n";
    exit;
}
