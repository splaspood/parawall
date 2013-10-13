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

			setter :in_interface, :out_interface, :proto, :jump, :match, :limit, :log_prefix, :log_level, :type, :comment

			def initialize(n, table, chain)
				@name   = n.to_s
				@jump   = :DROP
				@chain  = chain
				@table  = table
				@source = Array.new
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

				@source << '0.0.0.0/0' if @source.size == 0
				@destination << '0.0.0.0/0' if @destination.size == 0

				@source.each do |s|
					@destination.each do |d|
						arguments = {
							in_interface:     @in_interface,
							out_interface:    @out_interface,
							source:           s,
							source_port:      @source_port,
							destination:      d,
							destination_port: @destination_port,
							proto:            @proto,
							jump:             @jump,
							match:            @match,
							limit:            @limit,
							log_prefix:       @log_prefix,
							log_level:        @log_level,
							state:            @state,
							comment:          @comment
						}

						t = determine_type(s, d)

						t.each do |ti|
							output += build_command(ti, arguments)
						end
					end
				end

				output
			end

			private

			def build_command(type, arguments = {})
				IPTables.new(type: type, command: "--table #{@table} --append #{@chain} " + build_args(arguments) + "--match comment --comment \"#{@name}\"").to_s
			end

			def build_args(arguments = {})
				args = String.new

				arguments.delete(:source)       if arguments[:source] == '0.0.0.0/0'
				arguments.delete(:destination)  if arguments[:destination] == '0.0.0.0/0'

				unless arguments[:source_port].nil?
					args += "--proto #{arguments[:proto]} --match multiport --source-ports #{arguments[:source_port].join(",")} "
					arguments.delete(:source_port)
					arguments.delete(:proto)
				end

				unless arguments[:destination_port].nil?
					args += "--proto #{arguments[:proto]} --match multiport --destination-ports #{arguments[:destination_port].join(",")} "
					arguments.delete(:destination_port)
					arguments.delete(:proto)
				end

				arguments.keys.select { |a| not arguments[a].nil? }.each do |k|
					arg_name = k.to_s.gsub("_","-")
					args += "--#{arg_name} #{arguments[k]} "
				end

				args
			end

			def determine_type(src = nil, dest = nil)
				unless src.nil? or src == '0.0.0.0/0'
					ip = IPAddr.new src
					return ip.ipv4? ? [ :IPV4 ] : [ :IPV6 ]
				end

				unless dest.nil? or dest == '0.0.0.0/0'
					ip = IPAddr.new dest
					return ip.ipv4? ? [ :IPV4 ]  : [ :IPV6 ]
				end

				if src == '0.0.0.0/0' and dest == '0.0.0.0/0'
					return [ :IPV4, :IPV6 ]
				end

				return [ :IPV4 ]
			end
		end
	end
end
