class tripwire (
    $local_passphrase,
    $site_passphrase,
    $package_name         = $tripwire::params::package_name,
    $tripwire_dir         = $tripwire::params::tripwire_dir,
    $tripwire_email       = $tripwire::params::tripwire_email,
    $tripwire_policy_file = $tripwire::params::tripwire_policy_file,
    ) inherits tripwire::params  {

    # install the tripwire package
    package { $package_name:
        ensure => 'latest'
    }

    # generate a site key
    exec {'generate-site-key':
        command => "twadmin --generate-keys --site-keyfile ${tripwire_dir}/site.key -Q ${site_passphrase}",
        creates => "${tripwire_dir}/site.key",
        require => Package[$package_name],
        notify  => [Exec['sign-config-file'], Exec['sign-policy-file']],
    }

    # generate a local key
    exec {'generate-local-key':
        command => "twadmin --generate-keys --local-keyfile ${tripwire_dir}/${::fqdn}-local.key -P ${local_passphrase}",
        creates => "${tripwire_dir}/${::fqdn}-local.key",
        require => Package[$package_name],
    }

    # sign config file
    exec {'sign-config-file':
        command     => "twadmin --create-cfgfile --cfgfile ${tripwire_dir}/tw.cfg --site-keyfile ${tripwire_dir}/site.key -Q ${site_passphrase} ${tripwire_dir}/twcfg.txt",
        refreshonly => true,
        require     => [Exec['generate-site-key'],Exec['generate-local-key']],
    }

    # sign policy file
    exec { 'sign-policy-file':
        command     => "twadmin --create-polfile --cfgfile ${tripwire_dir}/tw.cfg --site-keyfile ${tripwire_dir}/site.key -Q ${site_passphrase} ${tripwire_dir}/twpol.txt",
        refreshonly => true,
        require     => [Exec['generate-site-key'],Exec['generate-local-key'],Exec['sign-config-file']],
        notify      => Exec['init-tripwire-database'],
    }

    # initialise the database
    exec { 'init-tripwire-database':
        command     => "tripwire --init -P ${local_passphrase}",
        refreshonly => true,
    }

    # if a policy file source is specified use it to populate twpol.txt
    if ($tripwire_policy_file != false and $tripwire_policy_file != 'false') {
        file { "${tripwire_dir}/twpol.txt":
            source => $tripwire_policy_file,
            notify => Exec['sign-policy-file'],
        }
    }

    # if an tripwire email address is set configure the action variable to add it, if not configure the variable to remove it
    if ($tripwire_email != false and $tripwire_email != 'false') {
        $augtool_email_action = "set GLOBALEMAIL '${tripwire_email}'"
    } else {
        $augtool_email_action = 'rm GLOBALEMAIL'
    }

    # depending on the 'augtool_email_action' variable either add/update or remove the GLOBALEMAIL value
    augeas { 'update_tripwire_email':
        lens    => 'Simplevars.lns',
        incl    => "${tripwire_dir}/twcfg.txt",
        context => "/files/${tripwire_dir}/twcfg.txt",
        changes => $augtool_email_action,
        notify  => Exec['sign-config-file'],
        require => Package[$package_name]
    }
}