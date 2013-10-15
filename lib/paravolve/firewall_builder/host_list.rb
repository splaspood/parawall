require "pp"
require "ipaddr"
require "resolv"

module ParaVolve
  module FirewallBuilder
		class HostList < Chain

      HOST_LIST_TYPES = %w{ source destination }

      def initialize( name, table, options )
        @hosts  = Array.new
        @type   = 'source'

        super "list-" + name, table, options
      end

			def hosts(hl=nil)
        return @hosts if hl.nil?

        hl = [ hl ] unless hl.is_a?(Array)

        @hosts = hl

				r = Rule.new(@name, @table, @name)
        
        r.send(@type.to_s.downcase, hl)
        r.jump(:ACCEPT)
        r.comment(false)

	  		@rules << r
			end

      def type(type)
        raise "type must be one of #{HOST_LIST_TYPES.join(", ")}" unless HOST_LIST_TYPES.include?(type)
        @type = type

        if @rules.size > 0
          @rules = Array.new
          hosts(@hosts)
        end
      end
		end
	end
end

