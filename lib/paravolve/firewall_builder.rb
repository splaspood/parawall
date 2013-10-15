require "ipaddr"
require "resolv"

require "paravolve/firewall_builder/iptables"
require "paravolve/firewall_builder/firewall"
require "paravolve/firewall_builder/table"
require "paravolve/firewall_builder/chain"
require "paravolve/firewall_builder/rule"

module ParaVolve
  module FirewallBuilder
    def self.configure(name, &block)
      fw = Firewall.new(name)
      fw.instance_eval(&block)
			fw
    end
  end
end
