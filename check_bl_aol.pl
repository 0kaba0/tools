#!/usr/bin/perl
##############################################################
#  Script     : check_bl_aol
#  Version    : 1.28
#  Author     : Igor Ru
#  Date       : 11/16/2017
#  Last Edited: 04/03/2018, igor.ru
#  Description: script checks if IPs are blacklisted by AOL
##############################################################

use strict;
use warnings;

use IO::Socket::INET;
use IO::Handle;

my %status = ( 'OK' => 0, 'WARNING' => 1, 'CRITICAL' => 2, 'UNKNOWN' => 3 );
my $cache_file = "/tmp/server_mail_ip.cache";
my $bad_count = 0;
my $full_check_return;
my @ips_on = uniq(find_mail_ips());
my $code = "";
my $colBLUE="\033[1;34m";
my $colNC="\033[0m";
my $colRED="\033[0;31m";
my $colGREEN="\033[0;36m";
my $colEL = "\033[1;33m";
my $colW = "\033[1;37m";

my $DEBUG = 0;

if (! -f $cache_file)
{
    
    if ($DEBUG)
    {
	print $colRED."IP cache file not found\n\n".$colNC;
    }
    
    open(FF, ">>".$cache_file);
    
    foreach my $n (@ips_on)
    {
	my @ext_ips = split(/:/,$n);
	my $int_ip = $ext_ips[0];

	my $real_ipaddr = `curl --interface \"$int_ip\" ifconfig.co 2>/dev/null`;
	chomp($real_ipaddr);
	
	print FF $int_ip.":".$real_ipaddr."\n"; 
	
	my $check_return = check_aol_service($int_ip,$ext_ips[1]);
	
	if ($DEBUG)
	{
	    if ($int_ip eq $real_ipaddr)
	    {
		print $colBLUE.'IP: '.$colEL.$real_ipaddr.$colBLUE.' EHLO: '.$colEL.$ext_ips[1]." ".$check_return."\n\n".$colNC;
	    }
	    else
	    {
		print $colBLUE.'IP Int|Real: '.$colEL.$int_ip.' '.$real_ipaddr.$colBLUE.' EHLO: '.$colEL.$ext_ips[1]." ".$check_return."\n\n".$colNC;
	    }
	}
	
	if ($check_return =~ /CRITICAL/)
	{
	#    my @tmp_dd_retn = split(/;/,$check_return);
            my @tmp_dd_retn2 = split(/ /,$check_return);

	    if ($bad_count == 0)
	    {
		$full_check_return = "CHECK_AOL CRITICAL - IPs BLACKLISTED (".$real_ipaddr;
	    }
	    else
	    {
		$full_check_return = $full_check_return.",".$real_ipaddr;
	    }
	    $bad_count = $bad_count + 1;
	    $code = $tmp_dd_retn2[3]." ".$tmp_dd_retn2[4]." ".$tmp_dd_retn2[5];
	}
	else
	{
	    if ($check_return =~ /UNKNOWN/)
	    {
		print $check_return."\n";
		exit $status{UNKNOWN};
	    }
	}
    }
	
    close(FF);
    system("cat ".$cache_file." | sort | uniq >>".$cache_file.".tmp; mv ".$cache_file.".tmp ".$cache_file);
    
    if ($bad_count == 0)
    {
	print "Everithing OK\n";
	exit $status{OK};
    }
    else
    {
	if ($code ne "")
	{
	   $full_check_return = $full_check_return."). Return code: ".$code;
	}
	else
	{
	   $full_check_return = $full_check_return."). Return code: 554";
	}
	print $full_check_return."\n";
	exit $status{CRITICAL};
    }
}
else
{
    if ($DEBUG)
    {
	print $colGREEN."IP cache file found\n\n".$colNC;
    }
    
    foreach my $n (@ips_on)
    {
	my @ext_ips = split(/:/,$n);
	my $int_ip = $ext_ips[0];
	
	my $tmp_dd = `cat $cache_file | grep $int_ip`;
	
	chomp($tmp_dd);
	
	my @dd = split(/:/,$tmp_dd);
	
	my $real_ipaddr = $dd[1];
	
	if ($real_ipaddr)
	{
	    my $check_return = check_aol_service($int_ip,$ext_ips[1]);
	    
	    if ($DEBUG)
	    {
		if ($int_ip eq $real_ipaddr)
		{
		    print $colBLUE.'IP: '.$colEL.$real_ipaddr.$colBLUE.' EHLO: '.$colEL.$ext_ips[1]." ".$check_return."\n\n".$colNC;
		}
		else
		{
		    print $colBLUE.'IP Int|Real: '.$colEL.$int_ip.' '.$real_ipaddr.$colBLUE.' EHLO: '.$colEL.$ext_ips[1]." ".$check_return."\n\n".$colNC;
		}
	    }
	    
	    if ($check_return =~ /CRITICAL/)
	    {
	
	#	my @tmp_dd_retn = split(/;/,$check_return);
		my @tmp_dd_retn2 = split(/ /,$check_return);

		if ($bad_count == 0)
		{
		    $full_check_return = "CHECK_AOL CRITICAL - IPs BLACKLISTED (".$real_ipaddr;
		}
		else
		{
		    $full_check_return = $full_check_return.",".$real_ipaddr;
		}
		$bad_count = $bad_count + 1;
		$code = $tmp_dd_retn2[3]." ".$tmp_dd_retn2[4]." ".$tmp_dd_retn2[5]
	    }
	    else
	    {
		if ($check_return =~ /UNKNOWN/)
		{
		    print $check_return."\n";
		    exit $status{UNKNOWN};
		}
	    }
	    
	}
	else
	{
	    unlink $cache_file;
	}
    }
    
    if ($bad_count == 0)
    {
	print "Everithing OK\n";
	exit $status{OK};
    }
    else
    {
	if ($code ne "")
	{
	   $full_check_return = $full_check_return."). Return code: ".$code;
	}
	else
	{
	   $full_check_return = $full_check_return."). Return code: 554";
	}
	print $full_check_return."\n";
	exit $status{CRITICAL};
    }
}


sub check_aol_service
{

    my $Local_Addr = $_[0];
    my $Local_Addr_Hello = $_[1];
    
    my $count = 1;

    #need to review code to check all AOL servers if timeout

    my $aol_server = ""; 
    my $error_return = "";
    my $sock = undef;
    
    $aol_server = "mx-aol.mail.gm0.yahoodns.net";
    $sock = IO::Socket::INET->new( PeerAddr => $aol_server,
                               PeerPort => '25',
			       LocalAddr => $Local_Addr,
                               Proto    => 'tcp',
			       Timeout  => '6') or $error_return = "UNKNOWN; Can't connect to $aol_server from $Local_Addr. Reason: $!";

    if (! $sock)
    {
	$error_return = "UNKNOWN; Can't connect to AOL servers from $Local_Addr. Reason: connection time out";
	return $error_return;
    }

    my $i = 0;
    my $j = 0;
    my $error_string = "";
    
    while (my $line=<$sock>)
    {
	chomp $line;
	if ($line =~ /220 mta/)
	{
            if ($DEBUG) { print $colW.">>>> ".$colNC.$line."\n"; }
	    print $sock "ehlo ".$Local_Addr_Hello."\n";
            if ($DEBUG) 
	    {
	      print "<--- ehlo ".$Local_Addr_Hello."\n";
	      $line=<$sock>;
              print $colW.">>>> ".$colNC.$line;
	    }
	    $i = $i + 1;
	}
    
	if (($i == 1) && ($line =~ /250 STARTTLS/))
	{
	    if ($DEBUG) { print $colW.">>>> ".$colNC.$line."\n"; }
            print $sock "mail from: <postmaster\@privateemail.com>\n";
	    if ($DEBUG) 
	    {
	       print "<--- mail from: <postmaster\@privateemail.com>\n";
	       $line=<$sock>;
	       print $colW.">>>> ".$colNC.$line;
	    }
	    print $sock "rcpt to: <igor.ru\@aol.com>\n";
	    if ($DEBUG)
	    {
	       print "<--- rcpt to: <igor.ru\@aol.com>\n";
	       $line=<$sock>;
	       print $colW.">>>> ".$colNC.$line;
	    }
	    $i=2;    
	}

	if ($i == 2)
	{ 
	    if (($line =~ /554/) || ($line =~ /451/) || ($line =~ /421/))
	    {
	    	$error_string = $line;
	    	print $sock "QUIT\n";
	    	if ($DEBUG)
	    	{
	       	   print "<--- QUIT\n\n";
	    	}
	    	return $colRED."CRITICAL; AOL returns: ".$error_string;
	    }
	    else
	    {
	    	print $sock "QUIT\n";
	        if ($DEBUG)
                {
               	   print "<--- QUIT\n\n";
            	}
            	return $colGREEN."OK";
	    }
	}
	
    }
}

sub find_mail_ips
{
    my $count = 0;
    my $bind_addr;
    my $helo_name;
    my @output_data = ();
    my $c2 = 0;
    
    open (FF, '/bin/cat /etc/postfix/master.cf | ');
    while(<FF>)
    {
        chomp();
        my $s = $_;

        if ($s =~ /\-o smtp\_bind\_address\=/)
        {
            $count = 1;
            $c2 = 0;
        }
                                                
        if ($count >= 1 and $count <3)
        {
	    my @t = split(/(=)/, $s);
                                                    
            my $temp1 = $t[0];
                                                                
            if ($temp1 =~ /smtp\_bind\_address/)
            {
                $bind_addr = $t[2];
                $c2 = $c2 + 1;
    	    }
            
            if ($temp1 =~ /smtp\_helo\_name/)
            {
                $helo_name = $t[2];
                $c2 = $c2 + 1;
            }
                                                                                                                                                                
            if ($c2 == 2)
            {
                push @output_data, $bind_addr.':'.$helo_name;
                $c2 = 0;
            }

            $count = $count + 1;
        }
        else
        {
            $count = 0;
	}
    }
    
    close(FF);
    return @output_data;
}

sub uniq {
    my %seen;
    grep !$seen{$_}++, @_;
}


