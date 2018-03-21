# lsyncd Module
[![Build Status](https://travis-ci.org/Adaptavist/puppet-tripwire.svg?branch=master)](https://travis-ci.org/Adaptavist/puppet-tripwire)

## Overview

The **tripwire** module handles the installation and configuration of tripwire

## Configuration

###`local_passphrase`

The Passphrase to set for the `local` key, no default (mandatory)

###`site_passphrase`

The Passphrase to set for the `site` key, no default (mandatory)

###`package_name`

The name of the tripwire package **Default: tripwire** 

###`tripwire_dir`

The location of the tripwire configuration directory **Default: /etc/tripwire**

###`tripwire_email`

The email address to add to tripwires config file, this address will be used to send the output of the scheduled reports, a value of false means no value. **Default: 'false'**

###`tripwire_policy_file`

The location of a file to use as a source for the tripwire policy file, a value of false no source and as such wil leave the out of the box policy file in place. **Default: 'false'**

##Hiera Examples:

    tripwire::local_passphrase: 'supersecret_local'
    tripwire::site_passphrase: 'supersecret_site'
    tripwire::tripwire_email: 'tripwire@example.com'
    tripwire::tripwire_policy_file: '/etc/puppet/files/tripwire-config.txt'


## Dependencies

This module depends on the puppetlabs "stdlib" module
