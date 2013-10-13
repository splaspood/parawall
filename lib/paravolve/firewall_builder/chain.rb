require "pp"
require "ipaddr"
require "resolv"

module ParaVolve
  module FirewallBuilder
		class Chain
			POLICIES = [ :ACCEPT, :DROP ]

			attr_accessor :name, :rules, :table

			def initialize(name, table)
				@name           = name.to_s
				@table          = table.to_s
				@default_policy = :DROP
				@rules          = Array.new
			end

			def rule(name, &block)
				r = Rule.new(name, @table, @name)
				r.instance_eval(&block)
				@rules << r
			end

			def default_policy(policy = nil)
				if policy.nil?
					@default_policy
				else
					raise "Default policy must be one of: #{POLICIES.join(" ")}" unless POLICIES.include?(policy)

					@default_policy = policy
				end
			end

			def to_s
				str  = "\n### Chain: #{@name}\n"

				unless %w{ INPUT OUTPUT FORWARD PREROUTING POSTROUTING }.include?(@name) 
					str += "#### Creating chain: #{@name}\n"
					str += create( @table, @name )
				else
					str += "#### Setting default policy to #{@default_policy.to_s}\n"
					str += set_default_policy( @table, @name, @default_policy.to_s )
				end

				str += @rules.map { |r|
					"\n# #{r.name}\n" + r.to_s
				}.join("\n")

				str
			end

			private

			def create( table, chain )
				IPTables.new( type: :BOTH, command: "--table #{table} --new #{chain}" ).to_s
			end

			def set_default_policy( table, chain, policy )
				IPTables.new( type: :BOTH, command: "--table #{table} --policy #{chain} #{policy}" ).to_s
			end
		end
	end
end

