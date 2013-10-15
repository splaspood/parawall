module ParaVolve
  module FirewallBuilder
		class Firewall
			attr_accessor :name, :tables

			def initialize(name = 'default')
				@name   = name.to_s
				@tables = Array.new
			end

			def table(name, options = { logging: true, flush: true, create: true }, &block)
        options[:flush] = true unless options.has_key?(:flush)

				t = Table.new(name, options)

        t.setup_logging if options.has_key?(:logging) and options[:logging]

        t.instance_eval(&block)
        
				@tables << t
			end

			def to_s
				@tables.map { |t| t.to_s }.join("")
			end
		end
	end
end

