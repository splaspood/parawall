module ParaVolve
  module FirewallBuilder
		class Firewall
			attr_accessor :name, :tables

			def initialize(name = 'default')
				@name   = name.to_s
				@tables = Array.new
			end

			def table(name, &block)
				t = Table.new(name)
				t.setup_logging
				t.instance_eval(&block)
				@tables << t
			end

			def to_s
				str = "\n# Firewall: #{@name}\n"
				str += @tables.map { |t| t.to_s }.join("\n")
				str
			end
		end
	end
end

