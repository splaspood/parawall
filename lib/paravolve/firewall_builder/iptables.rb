require 'pp'

module ParaVolve
	module FirewallBuilder
		class IPTables
			attr_accessor :type, :arguments

			def initialize( options = {} )
        @type       = options[:type]
        @arguments  = options[:arguments] || {}

        @type = [:IPV4, :IPV6]  if @type == :BOTH #or @type.nil?
				@type = [@type]         unless @type.is_a?(Array) or @type.nil?

        @arguments.delete_if { |k,v| v.nil? }
        @arguments.delete_if { |k,v| [:source, :destination].include?(k) and v == "0.0.0.0/0" }
			end

			def to_s
        build.join("\n") + "\n"
      end

      def execute
        build.each { |c| system(command) }
      end

      private

      def determine_type
        return @type unless @type.nil?

				if @arguments.has_key?(:source)
					ip = IPAddr.new arguments[:source]
					return ip.ipv4? ? [ :IPV4 ] : [ :IPV6 ]
				end

        if @arguments.has_key?(:destination)
					ip = IPAddr.new arguments[:destination]
					return ip.ipv4? ? [ :IPV4 ] : [ :IPV6 ]
				end

				return [ :IPV4, :IPV6 ]
			end

      def build
        cmd   = Array.new
        args  = @arguments.dup
        
        args.delete_if { |k,v| v.nil? }
        args.delete_if { |k,v| [:source, :destination].include?(k) and v == "0.0.0.0/0" }

        cmd += [ "--table", args.delete(:table) ]

        cmd += [ "--append", args.delete(:chain) ]  if args.has_key?(:chain)
        cmd += [ "--flush" ]                        if args.delete(:flush)
        cmd += [ "-X" ]                             if args.delete(:X)

        unless args[:comment] == false or args[:comment].nil?
          cmd += [ "--match", "comment", "--comment", '"' + args.delete(:comment) + '"' ] 
        else
          args.delete(:comment)
        end

        [ :source_port, :destination_port ].each do |k|
          if args.has_key?(k)
            cmd += [ "--proto",                     args.delete(:proto) ]
            cmd += [ "--match",                     "multiport"         ]
            cmd += [ "--#{k.to_s.gsub("_","-")}s",  args.delete(k)      ]
          end
        end

        args[:log_prefix] = "\"#{args[:log_prefix]}\"" if args.has_key?(:log_prefix)

        args.each_pair do |arg, val|
          cmd += [ "--#{format_argument(arg)}", val ]
        end

        determine_type.map do |t|
          full = [ iptables_command(t) ] + cmd
          full.join(" ")
        end
      end

      def format_argument(name)
        name.to_s.gsub("_","-")
      end

      def iptables_command( type )
        type == :IPV4 ? "/sbin/iptables" : "/sbin/ip6tables"
      end
		end
	end
end
