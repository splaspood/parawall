module ParaVolve
	module FirewallBuilder
		class IPTables
			attr_accessor :type, :command

			def initialize( options = {} )
				@type = options[:type]
				@command = options[:command]
			end

			def to_s
				@type = [ :IPV4, :IPV6 ] if @type == :BOTH
				@type = [ @type ] unless @type.is_a?(Array)

				str = String.new

				@type.each do |t|
					str += t == :IPV4 ? "/sbin/iptables " : "/sbin/ip6tables "
					str += @command + "\n"
				end

				str
			end
		end
	end
end
