module ParaVolve
  module FirewallBuilder
		class Table
			attr_accessor :name, :chains

			def initialize(name = 'filter')
				@name   = name.to_s
				@chains = Array.new
			end

			def chain(name, &block)
				c = Chain.new(name, @name)
				c.instance_eval(&block)
				@chains << c
			end

      def host_list(name, &block)
        hl = HostList.new(name, @name)
        hl.instance_eval(&block)
        @chains << hl
      end

			def to_s
				str  = "\n## Table: #{@name}\n"
				str += flush
				str += @chains.map { |c| c.to_s }.join("\n")
				str
			end

			def flush
				str	 = String.new
				str += "\n## Flushing table\n"

				[ :IPV4, :IPV6 ].each do |type|
					str += IPTables.new( type: type, command: "--table #{@name} --flush" ).to_s
					str += IPTables.new( type: type, command: "--table #{@name} -X" ).to_s

					str += IPTables.new( type: type, command: "--table #{@name} --policy INPUT DROP" ).to_s
					str += IPTables.new( type: type, command: "--table #{@name} --policy OUTPUT ACCEPT" ).to_s
					str += IPTables.new( type: type, command: "--table #{@name} --policy FORWARD DROP" ).to_s
				end

				str
			end

			def setup_logging
				c = Chain.new( "LOG_REJECT", "filter" )

				r = Rule.new "logging log", "filter", "LOG_REJECT"
				r.match('limit')
				r.limit('1/sec')
				r.log_prefix('IPT: ')
				r.log_level(7)
				r.jump(:LOG)
				r.type( [ :IPV4, :IPV6 ] )
				c.rules << r

				r = Rule.new "logging reject", "filter", "LOG_REJECT"
				r.jump(:REJECT)
				r.type( [ :IPV4, :IPV6 ] )
				c.rules << r

				@chains << c
			end
		end
	end
end

