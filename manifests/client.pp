class ssh_hardening::client (
  $cbc_required = false,
  $weak_hmac = false,
  $weak_kex = false,
  $ports = 22,
  $options      = {},
  $ipv6_enabled = false
) {
  if $ipv6_enabled == true {
    $addressfamily = 'any'
  } else {
    $addressfamily = 'inet'
  }

  $ciphers = get_ssh_ciphers($::operatingsystem, $::operatingsystemrelease, $cbc_required)
  $macs = get_ssh_macs($::operatingsystem, $::operatingsystemrelease, $weak_hmac)
  $kex = get_ssh_kex($::operatingsystem, $::operatingsystemrelease, $weak_kex)

  # create ssh_config and set permissions to root/644
  file {'/etc/ssh/ssh_config':
    ensure => 'file',
    content => template('ssh_hardening/ssh_config.erb'),
    owner  => 'root',
    group  => 'root',
    mode => '0644'
  }

}
