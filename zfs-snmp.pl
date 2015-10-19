#!/usr/bin/perl -w

#
# This is an sub-agent built for monitoring ZFS on Linux
# via the net-snmp(d) agent.
#
# To load this into a running agent with embedded perl support turned
# on in net-snmpd, simply put the following line (without the leading # mark)
# your snmpd.conf file:
#
#  perl do "/path/to/zfs-snmp.pl";
#
# Alternatively, if you do not have embedded perl support turned on,
# (eg Fedora Core snmpd is not built with embedded perl support) you can use
# this program separately as a sub-agent. Add this line to your snmpd.conf:
#
#  master agentx
#
# Then run and background the script, eg in rc.local:
#  /path/to/zfs-snmp.pl > /var/log/zfs-snmp.log 2>&1  &
# You wil require the NetSNMP perl modules for this module to work.
# installed (eg, in Fedora Core: yum install net-snmp-perl).
#
# This script works by gathering ZFS information from /proc/spl/kstat/zfs and
# invocation of zfs command.
# The latter requires elevated user permissions, which are gained throw sudo.
# Make sure, you have the following sudoers directive enabled:
#   snmp ALL=NOPASSWD:/sbin/zfs
# (Assuming your snmpd runs under uid "snmp" and your zfs binary is located
#  in /sbin)
#
# Thanks to Craig Macdonald <craig{at symbol}macdee.net>, who provided
# a good base for this with his nfsstats.pl.
#
# Joerg Delker <jd{at symbol}onix.de>
#

BEGIN {
    print STDERR "starting $0\n";
}

# set to 1 to get extra debugging information
my $debugging = 1;

# where to answer queries from
my $SOURCEOID = '.1.3.6.1.4.1.3724.1';    #corresponds to enterprises.3724.1

# how long to cache /proc/net/rcp/nfs and /proc/net/rcp/nfsd results for, in seconds
my $CACHE_TIME = 30;

#name that module gives to snmpd
my $NAME = 'ZFSSTATS';

# proc FS base for ZFS
my $PROCZFS
 = '/proc/spl/kstat/zfs';

#use strict breaks embedded perl support, so leave out
#use strict; my $agent;

use NetSNMP::OID;
use NetSNMP::agent;
use NetSNMP::ASN;

use Data::Dumper;

my $REGAT = new NetSNMP::OID($SOURCEOID);

my $COMMON = $REGAT . '.0';
my $POOL   = $REGAT . '.1';

my $O_ARCSTATS  = $COMMON . '.0';
my $O_ZIL       = $COMMON . '.1';
#my $O_DMU_TX    = $COMMON . '.2';
#my $O_FM        = $COMMON . '.3';
#my $O_VDEVCACHE = $COMMON . '.4';
#my $O_XUIO      = $COMMON . '.5';
#my $O_ZFETCH    = $COMMON . '.6';
#my $O_ZIL       = $COMMON . '.7';

my $O_POOL_IDX  = $POOL . '.0';
my $O_POOL_NAME = $POOL . '.1';
my $O_POOL_IO   = $POOL . '.2';



#cache statistics in these hashes. Cache age stored in scalars
#cache expired after $CACHE_TIME
my $common_cache_time = 0;
my $common_cache={};
my $pool_cache_time = 0;
my $pool_cache= {};

# fill caches
update_common_cache();
update_pool_cache();

# register OIDs
my $oidmap=build_oidmap();

my @ks = sort { $a <=> $b } map { $_ = new NetSNMP::OID($_) } keys %$oidmap;
my $lowestOid  = $ks[0];
my $highestOid = $ks[$#ks];

if ($debugging) {
    foreach my $k (@ks) {
        print STDERR "$k -> " . $oidmap->{$k} . "\n";
    }
}

print STDERR "$0 loaded ok\n" if $debugging;

my $running = 0;

# if we're not embedded, this will get auto-set below to 1
my $subagent = 0;

# where we are going to hook onto
my $regoid = new NetSNMP::OID($REGAT);
print STDERR "registering at " . $regoid . "\n" if ($debugging);

# If we're not running embedded within the agent, then try to start
# our own subagent instead.
if ( !$agent ) {
    $agent = new NetSNMP::agent(
        'Name'   => $NAME . '_Agent',    # reads test.conf
        'AgentX' => 1
    );                                   # make us a subagent
    if ( !defined $agent ) {
        print STDERR " Failed to connect to master, exiting $0\n";
        exit -1;
    }
    $subagent = 1;
    print STDERR "started us as a subagent ($agent)\n";
}

# we register ourselves with the master agent we're embedded in.  The
# global $agent variable is how we do this:
$agent->register( $NAME, $regoid, \&my_snmp_handler );

if ($subagent) {
    # We need to perform a loop here waiting for snmp requests.  We
    # aren't doing anything else here, but we could.
    $SIG{'INT'}  = \&shut_it_down;
    $SIG{'QUIT'} = \&shut_it_down;
    $running     = 1;
    while ($running) {
        $agent->agent_check_and_process(1);    # 1 = block
        print STDERR "mainloop excercised\n" if ($debugging);
    }
    $agent->shutdown();
}

######################################################################
# define a subroutine to actually handle the incoming requests to our
# part of the OID tree.  This subroutine will get called for all
# requests within the OID space under the registration oid made above.

sub my_snmp_handler {

    my ( $handler, $registration_info, $request_info, $requests ) = @_;
    eval {
        my $request;

        print STDERR "refs: ",
          join( ", ",
            ref($handler),      ref($registration_info),
            ref($request_info), ref($requests) ),
          "\n";

        print STDERR "processing a request of type "
          . $request_info->getMode() . "\n"
          if ($debugging);

        my $time = time;

        for ( $request = $requests ; $request ; $request = $request->next() ) {
            my $oid = $request->getOID();
            print STDERR "  processing request of $oid\n";

            if ( $request_info->getMode() == MODE_GET ) {

                #all main get code happens in set_value
                set_value( $request, $oid );

            }
            elsif ( $request_info->getMode() == MODE_GETNEXT ) {

                # if the requested oid is lower than ours, then return ours
                print STDERR " query:$oid low:$lowestOid high:$highestOid "
                  . ref($oid) . "  "
                  . ref($lowestOid) . "  "
                  . ref($highestOid) . "\n";
                if ( $oid < $lowestOid ) {
                    set_value( $request, $lowestOid );
                }
                elsif ( $oid < $highestOid
                  ) #request is somewhere in our range, so return first one after it
                {
                    my $i        = 0;
                    my $oidToUse = undef;

                    #linear search of sorted keys array.
                    do {
                        $oidToUse = $ks[$i];
                        $i++;

#print STDERR "Comparing $oid to $oidToUse ".ref($oid)." ".ref($oidToUse).
#  " cmp=".NetSNMP::OID::compare($oid, $oidToUse)." cmp2=".($oid <= $oidToUse)."\n";
                      } while ( NetSNMP::OID::compare( $oid, $oidToUse ) > -1
                        and $i < scalar @ks );

                    #got one to return
                    if ( defined $oidToUse ) {
                        print STDERR " Next oid to $oid is $oidToUse\n"
                          if ($debugging);
                        set_value( $request, $oidToUse );
                    }
                }
            }    #/if request type

        }    #/for
    };    #/eval
    if ($@) {
        print STDERR
          "  some problem in request processing loop, caught by eval: $@";
    }

    print STDERR "  finished processing\n"
      if ($debugging);
}

sub shut_it_down {
    $running = 0;
    print STDERR "shutting down $0\n" if ($debugging);
}

# give a $request a value by $oid
sub set_value {
    my ( $request, $oid ) = @_;
    warn "looking up $oid\n";
    my $expr = $oidmap->{$oid};
    if ( !defined $expr ) {
        print STDERR ( scalar localtime )
          . " --> error finding expression for $oid\n";
        return;
    }
    my $value = get_value($expr);
    if ( defined $value ) {
        if ($debugging) {
            print STDERR " $oid -> $lowestOid\n";
            print STDERR ( scalar localtime ) . "  -> ($expr) $value\n";
        }
        $request->setOID($oid);
        if ( !$request->setValue( ASN_COUNTER, '' . $value ) ) {
            warn "Error setting $oid value: $!\n";
        }
    }
    else {
        print STDERR ( scalar localtime )
          . "  -> error getting value from $expr for $oid\n";
    }
}




#find a value from a string counter name
sub get_value {
    my $expr = shift;
    return undef unless defined $expr;
    my $value = undef;
    my $time = time;

    if ( $expr =~ /^.pool/ ) {
        if ( $time - $pool_cache_time > $CACHE_TIME ) {
            update_pool_cache();
        }
        $value = eval($expr);
    }
    elsif ( $expr =~ /^.common/ ) {
        if ( $time - $common_cache_time > $CACHE_TIME ) {
            update_common_cache();
        }
        $value = eval($expr);
    }
    return $value;
}


sub update_common_cache {
    $common_cache_time = time;
    $common_cache->{'arcstats'} = read_stats('arcstats');
    $common_cache->{'zil'} = read_stats('zil');
}

sub update_pool_cache {
  my @pools = read_pools();

  foreach my $pool (@pools) {
    $pool_cache->{$pool} = {
      'name' => $pool,
      'io' => read_pool_io($pool)
    };
  }
}

sub build_oidmap {
  my %omap=(
    %{register_arcstats_opts()},
    %{register_pool_opts()}
  );
  return \%omap;
}

sub register_arcstats_opts {
  my $idx = 0;
  my $href={};
  foreach my $key (keys %{$common_cache->{'arcstats'}}) {
    $href->{$O_ARCSTATS.'.'.$idx}='$common_cache->{arcstats}->{'.$key.'}';
    $idx++;
  }
  return $href;
}

sub register_pool_opts {
  my $p_idx=0;
  my $href={};
  foreach my $pool (keys %$pool_cache) {
    $href->{$O_POOL_IDX.'.'.$p_idx}=$p_idx;
    $href->{$O_POOL_NAME.'.'.$p_idx}='$pool_cache->{'.$pool.'}->{name}';
    my $io_idx=0;
    foreach my $iostat (keys %{$pool_cache->{$pool}->{'io'}}) {
      $href->{$O_POOL_IO.'.'.$io_idx.'.'.$p_idx}='$pool_cache->{'.$pool.'}->{io}->{'.$iostat.'}';
      $io_idx++;
    }
    $p_idx++;
  }
  return $href;
}


sub read_stats {
  my $statfile=shift;
  my $stats={};
  open( PROCI, "<".$PROCZFS."/".$statfile ) || die "can't open $PROCZFS/$statfile: $!";
  while (<PROCI>) {
    chomp;
    if (/^([^ ]+)\s+(\d+)\s+(\d+)$/) {
        $stats->{$1}=$3;
    }
  }
  close PROCI;
  return $stats;
}

sub read_pools {
  opendir( my $dh, $PROCZFS ) || die "can't opendir $PROCZFS: $!";
  my @pools = grep { /[^.]/ && -d "$PROCZFS/$_" } readdir($dh);
  closedir $dh;

  return @pools;
}

sub read_pool_io {
  my $pool = shift;

  my @headers;
  my @values;
  my $stats={};
  # read io stats
  open( PROCI, "<".$PROCZFS."/".$pool."/io" );
  while (<PROCI>) {
    chomp;
    if (/^(?:([[:alpha:]])+\s+)+$/) { # headers
      @headers = split /\s+/, $_;
    } elsif (/^(?:([[:digit:]]+)\s+)+/) { # stats
      @values = split /\s+/, $_;
    }
  }
  close PROCI;

  for my $i (00 .. $#headers) {
    $stats->{$headers[$i]}=$values[$i];
  }
  return $stats;
}
