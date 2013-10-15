module ParaVolve
  module FirewallBuilder
		class Table
			attr_accessor :name, :chains

			def initialize(name = 'filter', options = { flush: true, type: :BOTH } )
				@name   = name.to_s
				@chains = Array.new

        @flush  = options[:flush]
        @type   = options[:type]
			end

			def chain(name, options = { create: true }, &block)
				c = Chain.new(name, @name, options)
				c.instance_eval(&block)
				@chains << c
			end

      def host_list(name, options = { set_policy: true, create: true }, &block)
        hl = HostList.new(name, @name, options)
        hl.instance_eval(&block)
        @chains << hl
      end

			def to_s
				str  = flush if @flush
				str += @chains.map { |c| c.to_s }.join("")
				str
			end

			def flush
				str	 = String.new

        str += IPTables.new( type: @type, arguments: { table: @name, flush: true } ).to_s
        str += IPTables.new( type: @type, arguments: { table: @name, X: true } ).to_s

        unless @name == 'nat'
          { INPUT: 'DROP', OUTPUT: 'ACCEPT', FORWARD: 'DROP' }.each_pair do |c, p|
            str += IPTables.new( type: @type, arguments: { table: @name, policy: "#{c} #{p}" } ).to_s
          end
        end

				str
			end

			def setup_logging
        [ :REJECT, :DROP ].each do |j|
          c = Chain.new( "log_and_#{j.to_s.downcase}", @name )

          r = Rule.new "#{j.to_s}->LOG", @name, "log_and_#{j.to_s.downcase}"
          r.match('limit')
          r.limit('1/sec')
          r.log_prefix('IPT: ')
          r.log_level(7)
          r.jump(:LOG)
          r.type(@type)
          r.comment(false)
          c.rules << r

          r = Rule.new "#{j.to_s}->LOG", @name, "log_and_#{j.to_s.downcase}"
          r.jump(j)
          r.type(@type)
          r.comment(false)
          c.rules << r

          @chains << c
        end
			end
		end
	end
end

