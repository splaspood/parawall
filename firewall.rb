require "ipaddr"
require "resolv"

module CustomFirewall
  def self.configure(name, &block)
    fw = Firewall.new(name)
    fw.instance_eval(&block)
    return fw
  end
end

class Firewall
  attr_accessor :name, :tables

  def initialize(name = 'default')
    @name   = name.to_s
    @tables = Array.new
  end

  def table(name, &block)
    t = Table.new(name)
    t.instance_eval(&block)
    @tables << t
  end

  def to_s
    str = "\n# Firewall: #{@name}\n"
    str += @tables.map { |t| t.to_s }.join("\n")
    str
  end
end

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

  def to_s
    str  = "\n## Table: #{@name}\n"
    str += @chains.map { |c| c.to_s }.join("\n")
    str
  end
end

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
      str += "/sbin/iptables --table #{@table} --new #{@name}\n"
      str += "/sbin/ip6tables --table #{@table} --new #{@name}\n"
    else
      str += "#### Setting default policy to #{@default_policy.to_s}\n"
      str += "/sbin/iptables --table #{@table} --policy #{@name} #{@default_policy.to_s}\n"
      str += "/sbin/ip6tables --table #{@table} --policy #{@name} #{@default_policy.to_s}\n"
    end

    str += @rules.map { |r|
      "\n# #{r.name}\n" + r.to_s
    }.join("\n")

    str
  end
end

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

  setter :in_interface, :out_interface, :source, :source_port, :destination,
    :destination_port, :proto, :jump, :match, :limit, :log_prefix, :log_level,
    :type, :comment

  def initialize(n, table, chain)
    @name   = n.to_s
    @jump = 'DROP'
    @chain  = chain
    @table  = table
  end

  def state(data=nil)
    if data.is_a? Array
      @state = data.join(",")
    else
      @state = data.to_s
    end
  end

  def source(data=nil)
    unless data.to_s =~ /^[0-9]/
      @source = Resolv.getaddress data
    else
      @source = data.to_s
    end
  end

  def destination(data=nil)
    unless data.to_s =~ /^[0-9]/
      @destination = Resolv.getaddress data
    else
      @destination = data.to_s
    end
  end


  def to_s
    @type = determine_type if @type.nil?

    output  = @type == :IPV4 ? "/sbin/iptables " : "/sbin/ip6tables "
    output += "--table #{@table} "
    output += "--append #{@chain} "
    output += build_args
    output += "--match comment --comment \"#{@name}\"\n"
 
    output
  end

  private

  def build_args
    args = String.new

    arg_list = [ :in_interface, :out_interface, :source, :source_port, :destination,
      :destination_port, :proto, :jump, :match, :limit, :log_prefix, :log_level, :state, :comment ]
    
    unless @match.nil?
      args += "--match #{instance_variable_get("@match")} "
      arg_list.delete(:match)
    end

    arg_list.select { |a| not instance_variable_get( "@#{a.to_s}" ).nil? }.each do |a|
      arg_name = a.to_s.gsub("_","-")
      args += "--#{arg_name} #{instance_variable_get("@#{a.to_s}")} "
    end

    args
  end

  def determine_type
    unless @destination.nil?
      ip = IPAddr.new @destination
      return ip.ipv4? ? :IPV4 : :IPV6
    end

    unless @source.nil?
      ip = IPAddr.new @source
      return ip.ipv4? ? :IPV4 : :IPV6
    end

    return :IPV4
  end
end
