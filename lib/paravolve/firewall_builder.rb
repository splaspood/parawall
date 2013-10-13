require "ipaddr"
require "resolv"

require "paravolve/custom_firewall/iptables"
require "paravolve/custom_firewall/firewall"
require "paravolve/custom_firewall/table"
require "paravolve/custom_firewall/chain"
require "paravolve/custom_firewall/rule"

module ParaVolve
  module FirewallBuilder
    def self.configure(name, &block)
      fw = Firewall.new(name)
      fw.instance_eval(&block)
			fw
    end
    
    def self.setup
			str  = "# Generated: #{Time.now}\n"
      str += "\n# Setup\n"

      str += IPTables.new( type: :IPV4, command: "--flush --table nat" ).to_s
      str += IPTables.new( type: :IPV4, command: "-X --table nat" ).to_s
      str += IPTables.new( type: :IPV4, command: "--table nat --append POSTROUTING --source 192.168.0.0/16 --out-interface eth0 --jump MASQUERADE" ).to_s

      str
    end
  end
end
