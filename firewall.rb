require "pp"
require "ipaddr"
require "resolv"

module ParaVolve
  module CustomFirewall
    def self.configure(name, &block)
      fw = Firewall.new(name)
      fw.instance_eval(&block)
      return fw
    end
    
    def self.setup
      str  = "# Setup\n"

      str += "/sbin/iptables -F\n"
      str += "/sbin/iptables -X\n"
      str += "/sbin/iptables -F -t nat\n"
      str += "/sbin/iptables -X -t nat\n"
      str += "/sbin/ip6tables -F\n"
      str += "/sbin/ip6tables -X\n"

      str += "/sbin/iptables -P INPUT DROP\n"
      str += "/sbin/iptables -P OUTPUT ACCEPT\n"
      str += "/sbin/iptables -P FORWARD DROP\n"

      str += "/sbin/ip6tables -P INPUT DROP\n"
      str += "/sbin/ip6tables -P OUTPUT ACCEPT\n"
      str += "/sbin/ip6tables -P FORWARD DROP\n"

      str += "iptables -t nat -A POSTROUTING -s 192.168.0.0/16 -o eth0 -j MASQUERADE\n"

      str

  #    setup_logging
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

  private

  def setup_logging
    c = Chain.new( "LOG_REJECT", "filter" )

    r = Rule.new "logging log", "filter", "LOG_REJECT"
    r.match('limit')
    r.limit('1/sec')
    r.log_prefix('IPT: ')
    r.log_level(7)
    r.jump(:LOG)
    r.type( [ :IPV4, :IPV6 ] )
    c.rules << r

    r = Rule.new "logging reject", "filter", "LOG_REJECT"
    r.jump(:REJECT)
    r.type( [ :IPV4, :IPV6 ] )
    c.rules << r

    puts c
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
    output = type == :IPV4 ? "/sbin/iptables " : "/sbin/ip6tables "
    output += "--table #{@table} "
    output += "--append #{@chain} "
    output += build_args(arguments)
    output += "--match comment --comment \"#{@name}\"\n"

    output
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
