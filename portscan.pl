#!/usr/bin/perl
# portscan -h for usage
# Created by John Tassano
# John.Tassano@Centurylink.com
# Version 1.4
# TCP Port scanner

use strict;
use Socket;
use Data::Validate::Domain;
use IO::Socket;
#use IO::Handle;
use Win32::Env;
use Win32::Clipboard;
use Net::Ping::External qw(ping);
$SIG{INT} = \&interrupt;

my $VERSION = '1.4';
$| = 1; # so \r works right, # flush the print buffer
print "\n";
print " PORTSCAN V$VERSION - TCP CONNECTION\n";
my $clip_enabled = 0;
my $clip = Win32::Clipboard::GetText() if ( $clip_enabled );
my ($ip, $protocol, $start_port, $end_port, $log, $host, $address, $path);
$protocol = getprotobyname('tcp');
($ip, $start_port, $end_port, $log) = @ARGV;
if (scalar(@ARGV) > 4)
{
	usage();
	print " Too Many Arguments\n";
	exit 1;
}

if ( $start_port > $end_port )
{
	usage();
	print " start port can't be greater then the end port. We can't go backwards yo.\n";
	exit 1;
}

if (!$ip) 
{
	# Get clipboard if its not super long.
	if( length($clip) < 50 && length($clip) > 1 && $clip_enabled)
	{
		$clip =~s/\n//g; # remove new line
		$ip = $clip;
		print " No input, getting Host from clipboard: $clip\n";
	}
	else
	{
		#print " No input, default to localhost 127.0.0.1\n";
	}
}

if ($ip eq "-h") 
{
    &usage();
	exit 1;
}

#Defaults
$path = $ENV{'USERPROFILE'};
$path =~s/\\/\//g;
if (!$ip)
{
	$ip = '127.0.0.1';
	usage();
}
$host = $ip;
$start_port = 1 if not $start_port;
$end_port = 100 if not $end_port;
$log = "$path/portscan.txt" if not $log;

my $ValidDomain = is_domain($host);
if ( $ValidDomain )
{
	my $resolve = inet_aton($host);
	$address ="Not valid";
	if ($resolve) 
	{
		$address = inet_ntoa($resolve);
		print " Name Resolution: $host $address \n";
		$ip = $address;
	}
	else
	{
		print " Unable to resolve $host\n";
	}
}

#match any number sperated by periods 
# m/^\d+\.\d+\.\d+\.\d+$/
#match valid ip address
# ^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$

if($ip !~  m/^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$/ and $ip ne "localhost")
{
	usage();
	print " Invalid IP Address $ip\n";
	exit 1;
}
else
{
	my $google = ping(host => '8.8.8.8'); # google dns
	my $alive = ping(host => $ip);
	if ($alive)
	{
		print " Host $ip is reachable\n"
	}
	else
	{
		if ( $google )
		{
			print " Host $ip is not reachable by icmp pings. Scanning anyways\n";
		}
		else
		{
			print " Check Internet Connection Host $ip and google unreachable\n";
			exit 1;
		}
	}
}

my $LOG_FILE;
#Open file and append
open($LOG_FILE, '>>', $log) or die "Can't open log file $log.\n";
# Make file handle hot so the buffer is flushed after every write
# Nasty way to autoflush the buffer.
select((select($LOG_FILE), $| = 1)[0]);
# Use IO::Handle 
#$LOG_FILE->autoflush(1);

print " LogFile: $log\n";
print " Scanning $ip for open ports $start_port - $end_port\n";
print "\n";

my $ports;
my @open_ports = ();
print " Press CTRL + C to terminate scan.\n";

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
        print "\n Port $port is open\n" ;
    }
}

my $datestring = gmtime();
print " Scan Completed $datestring\n";
print $LOG_FILE "\nGMT date and time $datestring\n";
print $LOG_FILE "Finished Scanning $ip between port $start_port and $end_port\n";

if ($ports) 
{
	print " The following ports are open on $ip port ";
	print $LOG_FILE "The following ports are open on $ip port ";
	
	foreach my $port(@open_ports) 
	{ 
		print "$port, ";
		print $LOG_FILE "$port, ";
	}
}
else
{
	print " No open ports found for Host $ip\n";
	print $LOG_FILE "No open ports found for Host $ip\n";
}

print "\n";
print $LOG_FILE "\n";
close $LOG_FILE;

sub usage 
{
	print " Defaults: portscan 127.0.0.1 1 100 portscan.txt\n";
    print " Usage: portscan [host] [start_port] [end_port] [logfile]\n";
}

sub interrupt {
	close $LOG_FILE;
	die "\n Terminating port scan\n";
    exit 1;
}

exit 1;
