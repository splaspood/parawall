require "ipaddr"
require "resolv"

module ParaVolve
  module FirewallBuilder
		class Rule
      ## Dynamic

      def self.jumpers(*method_names)
        method_names.each do |name|
          send :define_method, name do
            case name
            when :accept
              instance_variable_set( '@jump'.to_sym, :ACCEPT )
            when :drop
              instance_variable_set( '@jump'.to_sym, :log_and_drop )
            when :reject
              instance_variable_set( '@jump'.to_sym, :log_and_reject )
            end
          end
        end
      end

      def self.csv_value(*method_names)
        method_names.each do |name|
          send :define_method, name do |data = nil|
            if data.nil?
              instance_variable_get( "@#{name}".to_sym )
            else
              data = [data] unless data.is_a?(Array)

              instance_variable_set( "@#{name}".to_sym, data.join(",") )
            end
          end
        end
      end

      def self.multiple_value(*method_names)
				method_names.each do |name|
					send :define_method, name do |data = nil|
						if data.nil?
							instance_variable_get "@#{name}".to_sym
						else
              data = [data] unless data.is_a?(Array)

							instance_variable_set "@#{name}".to_sym, data
						end
					end
				end
			end

      def self.standard(*method_names)
				method_names.each do |name|
					send :define_method, name do |data = nil|
						if data.nil?
							instance_variable_get "@#{name}".to_sym
						else
							instance_variable_set "@#{name}".to_sym, data
						end
					end
				end
			end

      def self.addresses(*method_names)
				method_names.each do |name|
					send :define_method, name do |data = nil|
            if data.nil?
              instance_variable_get "@#{name}".to_sym
            else
          		data = [data] unless data.is_a?(Array)

              resolved = data.map do |s|
					      unless s.to_s =~ /^[0-9]/
						      Resolv.getaddress s
					      else
						      s.to_s
					      end
				      end

              instance_variable_set( "@#{name}".to_sym, resolved )
            end
					end
				end
			end

      attr_accessor :name, :chain, :table

			standard        :in_interface, :out_interface, :proto, :jump, :match, :limit, :log_prefix, :log_level, :comment, :host_list
      addresses       :source, :destination
      multiple_value  :type
      csv_value       :state, :source_port, :destination_port
      jumpers         :accept, :drop, :reject


			def initialize(n, table, chain)
				@name        = n.to_s
				@jump        = :DROP
				@chain       = chain
				@table       = table
				@comment     = @name

				@source      = Array.new
				@destination = Array.new
			end

			def to_s
				output = String.new

				@source << '0.0.0.0/0'      if @source.size == 0
				@destination << '0.0.0.0/0' if @destination.size == 0

				@source.each do |s|
					@destination.each do |d|
						output += IPTables.new( type: @type, arguments: {
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
