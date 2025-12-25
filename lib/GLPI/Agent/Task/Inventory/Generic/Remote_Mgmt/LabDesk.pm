package GLPI::Agent::Task::Inventory::Generic::Remote_Mgmt::LabDesk;

# Based on the work done by Ilya published on no more existing https://fusioninventory.userecho.com site

use strict;
use warnings;

use parent 'GLPI::Agent::Task::Inventory::Module';

use English qw(-no_match_vars);

use GLPI::Agent::Tools;

sub _get_labdesk_config {
    return OSNAME eq 'MSWin32' ?
        'C:\Windows\ServiceProfiles\LocalService\AppData\Roaming\LabDesk\config\LabDesk.toml' :
        '/root/.config/labdesk/LabDesk.toml';
}

sub isEnabled {
    return has_file(_get_labdesk_config());
}

sub doInventory {
    my (%params) = @_;

    my $inventory = $params{inventory};
    my $logger    = $params{logger};

    my $conf = _get_labdesk_config();
    my $LabDeskID = getFirstMatch(
        file    => $conf,
        logger  => $logger,
        pattern => qr/^id\s*=\s*'(.*)'$/
    );

    # Add support for --get-id parameter available since LabDesk 1.2 as id becomes empty in conf
    # Only works starting with LabDesk v1.2.2
    unless (defined($LabDeskID) && length($LabDeskID)) {
        my $command = 'labdesk';
        if(OSNAME eq 'MSWin32'){
            GLPI::Agent::Tools::Win32->require();
            my $installLocation = GLPI::Agent::Tools::Win32::getRegistryValue(
                path   => "HKEY_LOCAL_MACHINE/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/LabDesk/InstallLocation",
                logger => $logger
            );
            $command = (empty($installLocation) ? 'C:\Program Files\LabDesk' : $installLocation) . '\labdesk.exe';
        }
        if (canRun($command)) {
            $command = '"'.$command.'"' if OSNAME eq 'MSWin32';
            my $required = 1;
            my $version = getFirstLine(
                command => $command." --version",
                logger  => $logger
            );
            if ($version && $version =~ /^(\d+)\.(\d+)\.(\d+)/) {
                $required = int($1) > 1 || (int($1) == 1 && int($2) > 2) || (int($1) == 1 && int($2) == 2 && int($3) >= 2) ? 0 : 1;
            }
            if ($required) {
                $logger->debug("Can't get LabDesk ID, at least LabDesk v1.2.2 is required") if $logger;
                return;
            }
            $LabDeskID = getFirstMatch(
                command => $command." --get-id",
                logger  => $logger,
                pattern => qr/^(\d+)$/
            );
            unless ($LabDeskID) {
                $logger->debug("Can't get LabDesk ID, LabDesk is probably not running") if $logger;
                return;
            }
        }
    }

    if (defined($LabDeskID)) {
        $logger->debug('Found LabDesk ID : ' . $LabDeskID) if $logger;

        $inventory->addEntry(
            section => 'REMOTE_MGMT',
            entry   => {
                ID   => $LabDeskID,
                TYPE => 'labdesk'
            }
        );
    } else {
        $logger->debug('LabDesk ID not found in '.$conf) if $logger;
    }
}

1;
