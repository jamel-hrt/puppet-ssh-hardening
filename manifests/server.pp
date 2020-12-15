class ssh_hardening::server (
  $cbc_required           = false,
  $weak_hmac              = false,
  $weak_kex               = false,
  $ports                  = 22,
  $listen_to              = [],
  $host_key_files         = [],
  $client_alive_interval  = 300,
  $client_alive_count     = 3,
  $allow_root_with_key    = false,
  $ipv6_enabled           = false,
  $use_pam                = true,
  $allow_tcp_forwarding   = false,
  $allow_agent_forwarding = false,
  $max_auth_retries       = 2,
  $options                = {},
) {

  $addressfamily = $ipv6_enabled ? {
    true  => 'any',
    false => 'inet',
  }

  $ciphers = get_ssh_ciphers($::operatingsystem, $::operatingsystemrelease, $cbc_required)
  $macs = get_ssh_macs($::operatingsystem, $::operatingsystemrelease, $weak_hmac)
  $kex = get_ssh_kex($::operatingsystem, $::operatingsystemrelease, $weak_kex)
  $priv_sep = use_privilege_separation($::operatingsystem, $::operatingsystemrelease)

  $permit_root_login = $allow_root_with_key ? {
    true  => 'without-password',
    false => 'no',
  }

  $use_pam_option = $use_pam ? {
    true  => 'yes',
    false => 'no',
  }

  $tcp_forwarding = $allow_tcp_forwarding ? {
    true  => 'yes',
    false => 'no'
  }

  $agent_forwarding = $allow_agent_forwarding ? {
    true  => 'yes',
    false => 'no'
  }

  service {'ssh':
    ensure  => 'running',
    enable  => 'true',
	}

  file {'/etc/ssh':
    ensure => 'directory',
    mode   => '0755',
    owner  => 'root',
    group  => 'root'
  }

  file {'/etc/ssh/revoked_keys':
    ensure => 'file',
    content => template('ssh_hardening/revoked_keys.erb'),
    owner  => 'root',
    group  => 'root',
    mode => '0600',
    notify => Service["ssh"]
  }

  # create sshd_config and set permissions to root/600
  file {'/etc/ssh/sshd_config':
    ensure => 'file',
    content => template('ssh_hardening/sshd_config.erb'),
    owner  => 'root',
    group  => 'root',
    mode => '0600',
    validate_cmd => '/usr/sbin/sshd -T -C user=root -C host=localhost -C addr=localhost -C lport=22 -f %',
    notify => Service["ssh"]
  }

  # remove all small primes
  exec {'/etc/ssh/moduli':
    command => "/usr/bin/awk '$5 >= 2048' /etc/ssh/moduli > /etc/ssh/moduli.new ;
         [ -r /etc/ssh/moduli.new -a -s /etc/ssh/moduli.new ] && mv /etc/ssh/moduli.new /etc/ssh/moduli || true",
    onlyif => "/usr/bin/test `/usr/bin/awk '$5 < 2048' /etc/ssh/moduli | /usr/bin/wc -l` -gt 0",
    notify => Service["ssh"]
  }
}
