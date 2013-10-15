require "paravolve/firewall_builder"
require "paravolve/firewall_builder/host_list"

module ParaVolve
  module CustomFirewall
    def self.configure(name, options = { debug: false }, block)
      str  = "#!/bin/bash\n"
      str += "set -x\n\n" if options.has_key?(:debug) and options[:debug]
      
      str += "# Generated: #{Time.now}\n"

      fw = FirewallBuilder::Firewall.new(name)
      fw.instance_eval(block, name)
			str += fw.to_s

      str
    end
  end
end
