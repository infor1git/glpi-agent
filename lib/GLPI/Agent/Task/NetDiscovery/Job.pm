package GLPI::Agent::Task::NetDiscovery::Job;

use strict;
use warnings;

use English qw(-no_match_vars);

use Net::IP;

use GLPI::Agent::Logger;

sub new {
    my ($class, %params) = @_;

    my $self = {
        logger          => $params{logger} || GLPI::Agent::Logger->new(),
        _params         => $params{params},
        _credentials    => $params{credentials},
        _ranges         => $params{ranges},
        _snmpwalk       => $params{file},
        _server         => $params{server},
    };
    bless $self, $class;
}

sub pid {
    my ($self) = @_;
    return $self->{_params}->{PID} // $self->{_params}->{pid} // 0;
}

sub timeout {
    my ($self) = @_;
    return $self->{_params}->{TIMEOUT} // $self->{_params}->{timeout} // 60;
}

sub max_threads {
    my ($self) = @_;
    return $self->{_params}->{THREADS_DISCOVERY} // $self->{_params}->{threads} // 1;
}

sub netscan {
    my ($self) = @_;
    return $self->{_netscan};
}

sub control {
    my ($self) = @_;
    return $self->{_control};
}

sub localtask {
    my ($self) = @_;
    return $self->{_localtask};
}

sub getQueueParams {
    my ($self, $range) = @_;

    my $start = $range->{start};
    my $end   = $range->{end};

    my $block = Net::IP->new( "$start-$end" );
    if (!$block || !$block->ip() || $block->{binip} !~ /1/) {
        $self->{logger}->error(
            "IPv4 range not supported by Net::IP: $start-$end"
        );
        return 0;
    }

    unless ($block->size()) {
        $self->{logger}->error("Skipping empty range: $start-$end");
        return 0;
    }

    $self->{logger}->debug("initializing block $start-$end");

    $range->{block} = $block;

    my $params = {
        size    => $block->size()->numify(),
        range   => $range
    };

    return 1, $params;
}

sub updateQueue {
    my ($self, %params) = @_;

    $self->{_queue}->{size} += $params{size};
    push @{$self->{_queue}->{ranges}}, $params{range} if $params{range};
}

sub queuesize {
    my ($self) = @_;

    return 0 unless $self->{_queue};

    return $self->{_queue}->{size} // 0;
}

sub started {
    my ($self) = @_;

    return 0 unless $self->{_queue};

    return 1 if $self->{_queue}->{started};

    # Be sure to return true next time
    $self->{_queue}->{started}++;
    return 0;
}

sub done {
    my ($self) = @_;

    return 0 unless $self->{_queue};

    $self->{_queue}->{in_queue} --;
    $self->{_queue}->{done} ++;

    return $self->{_queue}->{done} >= $self->{_queue}->{size} ? 1 : 0;
}

sub max_in_queue {
    my ($self) = @_;

    return 0 unless $self->{_queue};

    return $self->{_queue}->{in_queue} >= $self->max_threads() ? 1 : 0;
}

sub range {
    my ($self) = @_;

    return unless $self->{_queue};

    return $self->{_queue}->{ranges}->[0];
}

sub nextip {
    my ($self) = @_;

    return unless $self->{_queue};

    my $range = $self->{_queue}->{ranges}->[0];
    my $block = $range->{block};
    my $blockip = $block->ip();
    # Still update block and handle range list
    $range->{block} = $block + 1;
    shift @{$self->{_queue}->{ranges}} unless $range->{block};

    $self->{_queue}->{in_queue}++ if $blockip;

    return $blockip;
}

sub ranges {
    my ($self) = @_;

    # After _queue has been defined, return the queue ranges count
    return scalar(@{$self->{_queue}->{ranges}}) if $self->{_queue};

    my ($snmp_credentials, $remote_credentials) = $self->_getValidCredentials();

    $self->{_queue} = {
        in_queue            => 0,
        snmp_credentials    => $snmp_credentials   // [],
        remote_credentials  => $remote_credentials // [],
        ranges              => [],
        size                => 0,
        done                => 0,
    };

    my @ranges = ();

    foreach my $range (@{$self->{_ranges}}) {
        push @ranges, {
            ports   => _getSNMPPorts($range->{PORT} // $range->{port}),
            domains => _getSNMPProtocols($range->{PROTOCOL} // $range->{protocol}),
            entity  => $range->{ENTITY} // $range->{entity},
            start   => $range->{IPSTART} // $range->{start},
            end     => $range->{IPEND} // $range->{end},
            walk    => $self->{_snmpwalk},
        };
        # Support ToolBox model where credentials are linked to range
        if ($range->{NAME}) {
            my ($snmp_credentials, $remote_credentials) = $self->_getValidCredentials($range->{NAME});
            $thisrange->{snmp_credentials}   = $snmp_credentials   // [];
            $thisrange->{remote_credentials} = $remote_credentials // [];
        }
        push @ranges, $thisrange;
    }

    return @ranges;
}

sub getCredentialsFromGLPI {
    my ($self, %params) = @_;

    my $logger = $self->{logger};
    my $jobid  = $self->pid();

    GLPI::Agent::Protocol::GetParams->require();
    if ($EVAL_ERROR) {
        $logger->error("Unable to request SNMP credentials");
        return;
    }
    my $getparams = GLPI::Agent::Protocol::GetParams->new(
        deviceid    => $params{deviceid},
        params_id   => $jobid,
        use         => $self->{_server}.'_netdiscovery',
    );
    my $answer = $params{client}->send(
        url     => $params{url},
        message => $getparams
    );

    if ($answer) {
        my $status = $answer->get('status');
        my $credentials = $answer->get('credentials');
        if ($status eq 'ok' && $credentials) {
            if (@{$credentials}) {
                foreach my $credential (@{$credentials}) {
                    next unless ref($credential) eq 'HASH';
                    my $cred = {
                        ID      => $credential->{id},
                        VERSION => $credential->{version},
                    };
                    if (!defined($cred->{VERSION})) {
                        $logger->debug("SNMP credential without version received for jobid $jobid, assuming v1");
                        $cred->{VERSION} = '1';
                    }
                    if ($cred->{VERSION} eq '3') {
                        map {
                            $cred->{uc($_)} = $credential->{$_}
                        } grep { $credential->{$_} }
                            qw/username authpassword authprotocol privpassword privprotocol/;
                    } else {
                        $cred->{COMMUNITY} = $credential->{community} // 'public';
                    }
                    push @{$self->{_credentials}}, $cred;
                }
            } else {
                $logger->debug("No SNMP credential returned for jobid $jobid");
            }
        } elsif ($status eq 'error') {
            my $message = $answer->get('message') // 'no error given';
            $logger->debug("SNMP credential request error: $message");
        } else {
            $logger->error("Unsupported SNMP credentials request answer");
        }
    } else {
        $logger->error("Got no SNMP credentials for jobid $jobid");
    }

    return $self->getValidCredentials();
}

sub getValidCredentials {
    my ($self) = @_;

    return unless $self->{_queue};

    return $self->{_queue}->{snmp_credentials};
}

sub remote_credentials {
    my ($self) = @_;

    foreach my $credential (@{$self->{_credentials}}) {
        my $snmpv3 = defined($credential->{VERSION}) && $credential->{VERSION} eq '3' ? 1 : 0;
        if ($snmpv3 && !defined($credential->{USERNAME})) {
            # a user name is required for snmp v3
            $self->{logger}->info(
                "Not username provided".
                (defined($credential->{ID}) ? " with credentials ID $credential->{ID}":"").
                ", skipping"
            );
        } elsif ($snmpv3 && !Crypt::DES->require()) {
            # DES support is required for snmp v3
            $self->{logger}->info(
                "Crypt::DES perl module is missing to support SNMP v3".
                (defined($credential->{ID}) ? " for credentials ID $credential->{ID}":"").
                ", skipping"
            );
        } elsif (!defined($credential->{COMMUNITY})) {
            $self->{logger}->info(
                "Not community provided".
                (defined($credential->{ID}) ? " with credentials ID $credential->{ID}":"").
                ", skipping"
            );
        } else {
            push @credentials, $credential;
        }
    }

    $self->{logger}->warning("No valid SNMP credential defined for this scan")
        unless !$snmp || $valid_snmp;

    $self->{logger}->warning("No valid remote credential defined for this scan")
        unless !$remote || $valid_remote;

    return \@snmp_credentials, \@remote_credentials;
}

sub _getSNMPPorts {
    my ($ports) = @_;

    return [] unless $ports;

    # Given ports can be an array of strings or just a string and each string
    # can be a comma separated list of ports
    my @given_ports = map { split(/\s*,\s*/, $_) }
        ref($ports) eq 'ARRAY' ? @{$ports} : ($ports) ;

    # Be sure to only keep valid and uniq ports
    my %ports = map { $_ => 1 } grep { $_ && $_ > 0 && $_ < 65536 } @given_ports;

    return [ sort keys %ports ];
}

sub _getSNMPProtocols {
    my ($protocols) = @_;

    return [] unless $protocols;

    # Supported protocols can be used as '-domain' option for Net::SNMP session
    my @supported_protocols = (
        'udp',
        'udp/ipv4',
        'udp/ipv6',
        'tcp',
        'tcp/ipv4',
        'tcp/ipv6'
    );

    # Given protocols can be an array of strings or just a string and each string
    # can be a comma separated list of protocols
    my @given_protocols = map { split(/\s*,\s*/, $_) }
        ref($protocols) eq 'ARRAY' ? @{$protocols} : ($protocols) ;

    my @protocols = ();
    my %protocols = map { lc($_) => 1 } grep { $_ } @given_protocols;

    # Manage to list and filter protocols to use in @supported_protocols order
    foreach my $proto (@supported_protocols) {
        if ($protocols{$proto}) {
            push @protocols, $proto;
        }
    }

    return \@protocols;
}

1;
