require "pp"
require "ipaddr"
require "resolv"

module ParaVolve
  module FirewallBuilder
		class Rule
			def self.setter(*method_names)
				method_names.each do |name|
					send :define_method, name do |data = nil|
						if data.nil?
							instance_variable_get "@#{name}"
						else
							instance_variable_set "@#{name}".to_sym, data
						end
					end
				end
			end

			attr_accessor :name, :chain, :table

			setter :in_interface, :out_interface, :proto, :jump, :match, :limit, :log_prefix, :log_level, :type, :comment, :host_list

			def initialize(n, table, chain)
				@name        = n.to_s
				@jump        = :DROP
				@chain       = chain
				@table       = table
				@comment     = @name

				@source      = Array.new
				@destination = Array.new
			end

			def state(data=nil)
				if data.is_a? Array
					@state = data.join(",")
				else
					@state = data.to_s
				end
			end

			def source(data=nil)
				data = [ data ] unless data.is_a?(Array)
				
				@source = data.map do |s|
					unless s.to_s =~ /^[0-9]/
						Resolv.getaddress s
					else
						s.to_s
					end
				end
			end

			def destination(data=nil)
				data = [ data ] unless data.is_a?(Array)

				@destination = data.map do |d|
					unless d.to_s =~ /^[0-9]/
						Resolv.getaddress d
					else
						d.to_s
					end
				end
			end

			def type(data=nil)
				data = [ data ] unless data.is_a?(Array)
				@type = data
			end

			def destination_port(data=nil)
				data = [ data ] unless data.is_a?(Array)
				@destination_port = data
			end

			def source_port(data=nil)
				data = [ data ] unless data.is_a?(Array)
				@source_port = data
			end

			def to_s
				output = String.new

				@source << '0.0.0.0/0'      if @source.size == 0
				@destination << '0.0.0.0/0' if @destination.size == 0

				@source.each do |s|
					@destination.each do |d|
						output += IPTables.new( arguments: {
							in_interface:     @in_interface,
							out_interface:    @out_interface,
							source:           s,
							source_port:      @source_port,
							destination:      d,
							destination_port: @destination_port,
							proto:            @proto,
							jump:             @host_list.nil? ? @jump.to_s : "list-" + @host_list.to_s,
							match:            @match,
							limit:            @limit,
							log_prefix:       @log_prefix,
							log_level:        @log_level,
							state:            @state,
							comment:          @comment,
              table:            @table,
              chain:            @chain
						}).to_s
					end
				end

				output
			end
		end
	end
end
