require 'spec_helper'

local_passphrase = 'secret123'
site_passphrase = 'secret321'
fqdn = 'test123.example.com'
config_dir = '/etc/tripwire'
package_name = 'tripwire'
tripwire_email = 'tripwire@example.com'
tripwire_policy_file = '/tmp/twpolicy.txt'

describe 'tripwire', :type => 'class' do
    
  context "Should install tripwire, create keys, sign config/policy file and remove global email" do
    let(:params){{ 
      :local_passphrase => local_passphrase,
      :site_passphrase => site_passphrase,
      :tripwire_email => 'false',
      :tripwire_policy_file => 'false'
    }}
    let(:facts){{
      :fqdn => fqdn
    }}
    it do
      should contain_package('tripwire').with(
        'ensure'  => 'latest',
      )

      should contain_exec('generate-site-key').with(
        'command' => "twadmin --generate-keys --site-keyfile #{config_dir}/site.key -Q #{site_passphrase}",
        'creates' => "#{config_dir}/site.key",
        'require' => "Package[#{package_name}]",
        'notify'  => '[Exec[sign-config-file]{:command=>"sign-config-file"}, Exec[sign-policy-file]{:command=>"sign-policy-file"}]',
      )

      should contain_exec('generate-local-key').with(
        'command' => "twadmin --generate-keys --local-keyfile #{config_dir}/#{fqdn}-local.key -P #{local_passphrase}",
        'creates' => "#{config_dir}/#{fqdn}-local.key",
        'require' => "Package[#{package_name}]"
      )

      should contain_exec('sign-config-file').with(
        'command'     => "twadmin --create-cfgfile --cfgfile #{config_dir}/tw.cfg --site-keyfile #{config_dir}/site.key -Q #{site_passphrase} #{config_dir}/twcfg.txt",
        'refreshonly' => true,
        'require'     => '[Exec[generate-site-key]{:command=>"generate-site-key"}, Exec[generate-local-key]{:command=>"generate-local-key"}]',
      )

      should contain_exec('sign-policy-file').with(
        'command'     => "twadmin --create-polfile --cfgfile #{config_dir}/tw.cfg --site-keyfile #{config_dir}/site.key -Q #{site_passphrase} #{config_dir}/twpol.txt",
        'refreshonly' => true,
        'require'     => '[Exec[generate-site-key]{:command=>"generate-site-key"}, Exec[generate-local-key]{:command=>"generate-local-key"}, Exec[sign-config-file]{:command=>"sign-config-file"}]',
        'notify'      => 'Exec[init-tripwire-database]',
      )
      should contain_exec('init-tripwire-database').with(
        'command'     => "tripwire --init -P #{local_passphrase}",
        'refreshonly' => true,
      )

      should_not contain_file("#{config_dir}/twpol.txt")

      should contain_augeas('update_tripwire_email').with(
        'lens'    => 'Simplevars.lns',
        'incl'    => "#{config_dir}/twcfg.txt",
        'context' => "/files/#{config_dir}/twcfg.txt",
        'changes' => 'rm GLOBALEMAIL',
        'notify'  => "Exec[sign-config-file]",
        'require' => "Package[#{package_name}]",
      )
    end
  end

  context "add global email" do
    let(:params){{ 
      :local_passphrase => local_passphrase,
      :site_passphrase => site_passphrase,
      :tripwire_email => tripwire_email,
      :tripwire_policy_file => 'false',
    }}
    let(:facts){{
      :fqdn => fqdn
    }}
    it do
      should contain_package('tripwire').with(
        'ensure'  => 'latest',
      )

      should contain_exec('generate-site-key').with(
        'command' => "twadmin --generate-keys --site-keyfile #{config_dir}/site.key -Q #{site_passphrase}",
        'creates' => "#{config_dir}/site.key",
        'require' => "Package[#{package_name}]",
        'notify'  => '[Exec[sign-config-file]{:command=>"sign-config-file"}, Exec[sign-policy-file]{:command=>"sign-policy-file"}]',
      )

      should contain_exec('generate-local-key').with(
        'command' => "twadmin --generate-keys --local-keyfile #{config_dir}/#{fqdn}-local.key -P #{local_passphrase}",
        'creates' => "#{config_dir}/#{fqdn}-local.key",
        'require' => "Package[#{package_name}]"
      )

      should contain_exec('sign-config-file').with(
        'command'     => "twadmin --create-cfgfile --cfgfile #{config_dir}/tw.cfg --site-keyfile #{config_dir}/site.key -Q #{site_passphrase} #{config_dir}/twcfg.txt",
        'refreshonly' => true,
        'require'     => '[Exec[generate-site-key]{:command=>"generate-site-key"}, Exec[generate-local-key]{:command=>"generate-local-key"}]',
      )

      should contain_exec('sign-policy-file').with(
        'command'     => "twadmin --create-polfile --cfgfile #{config_dir}/tw.cfg --site-keyfile #{config_dir}/site.key -Q #{site_passphrase} #{config_dir}/twpol.txt",
        'refreshonly' => true,
        'require'     => '[Exec[generate-site-key]{:command=>"generate-site-key"}, Exec[generate-local-key]{:command=>"generate-local-key"}, Exec[sign-config-file]{:command=>"sign-config-file"}]',
        'notify'      => 'Exec[init-tripwire-database]',
      )
      should contain_exec('init-tripwire-database').with(
        'command'     => "tripwire --init -P #{local_passphrase}",
        'refreshonly' => true,
      )

      should_not contain_file("#{config_dir}/twpol.txt")

      should contain_augeas('update_tripwire_email').with(
        'lens'    => 'Simplevars.lns',
        'incl'    => "#{config_dir}/twcfg.txt",
        'context' => "/files/#{config_dir}/twcfg.txt",
        'changes' => "set GLOBALEMAIL '#{tripwire_email}'",
        'notify'  => "Exec[sign-config-file]",
        'require' => "Package[#{package_name}]",
      )
    end
  end

   context "add deploy policy file" do
    let(:params){{ 
      :local_passphrase => local_passphrase,
      :site_passphrase => site_passphrase,
      :tripwire_email => 'false',
      :tripwire_policy_file => tripwire_policy_file,
    }}
    let(:facts){{
      :fqdn => fqdn
    }}
    it do
      should contain_package('tripwire').with(
        'ensure'  => 'latest',
      )

      should contain_exec('generate-site-key').with(
        'command' => "twadmin --generate-keys --site-keyfile #{config_dir}/site.key -Q #{site_passphrase}",
        'creates' => "#{config_dir}/site.key",
        'require' => "Package[#{package_name}]",
        'notify'  => '[Exec[sign-config-file]{:command=>"sign-config-file"}, Exec[sign-policy-file]{:command=>"sign-policy-file"}]',
      )

      should contain_exec('generate-local-key').with(
        'command' => "twadmin --generate-keys --local-keyfile #{config_dir}/#{fqdn}-local.key -P #{local_passphrase}",
        'creates' => "#{config_dir}/#{fqdn}-local.key",
        'require' => "Package[#{package_name}]"
      )

      should contain_exec('sign-config-file').with(
        'command'     => "twadmin --create-cfgfile --cfgfile #{config_dir}/tw.cfg --site-keyfile #{config_dir}/site.key -Q #{site_passphrase} #{config_dir}/twcfg.txt",
        'refreshonly' => true,
        'require'     => '[Exec[generate-site-key]{:command=>"generate-site-key"}, Exec[generate-local-key]{:command=>"generate-local-key"}]',
      )

      should contain_exec('sign-policy-file').with(
        'command'     => "twadmin --create-polfile --cfgfile #{config_dir}/tw.cfg --site-keyfile #{config_dir}/site.key -Q #{site_passphrase} #{config_dir}/twpol.txt",
        'refreshonly' => true,
        'require'     => '[Exec[generate-site-key]{:command=>"generate-site-key"}, Exec[generate-local-key]{:command=>"generate-local-key"}, Exec[sign-config-file]{:command=>"sign-config-file"}]',
        'notify'      => 'Exec[init-tripwire-database]',
      )
      should contain_exec('init-tripwire-database').with(
        'command'     => "tripwire --init -P #{local_passphrase}",
        'refreshonly' => true,
      )

      should contain_file("#{config_dir}/twpol.txt").with(
        'source' => tripwire_policy_file,
        'notify' => "Exec[sign-policy-file]",
      )

      should contain_augeas('update_tripwire_email').with(
        'lens'    => 'Simplevars.lns',
        'incl'    => "#{config_dir}/twcfg.txt",
        'context' => "/files/#{config_dir}/twcfg.txt",
        'changes' => 'rm GLOBALEMAIL',
        'notify'  => "Exec[sign-config-file]",
        'require' => "Package[#{package_name}]",
      )
    end
  end

end
