
#! /usr/bin/ruby

require File.expand_path('../lib/dnstest', __FILE__)
require 'pp'


# algorithm
# Ask to the system configured resolver for the list of authoritative server for the starting level (may be root or tld or sub-tld)
# 
# For each one retrieve its SOA record and compile the delegation tree

# Find the resolver with newest SOA and ask him for authority for the full name's SOA
# If authoritative answer stop
# Otherwise repeat


# res = Dnsruby::Resolver.new # System default
# ret = res.query('example.com')
#
#puts "AAAAAAAAAAA #{ret.header.aa}"

class Log
  def debug(str)
    puts str
  end

  def info(str)
    puts str
  end

  def warn(str)
    puts str
  end
end

#class Log
#
#  def initialize
#    @text = ''
#  end
#
#  def debug(str)
#    @text << str
#  end
#
#  def info(str)
#    @text << str
#  end
#
#  def to_s
#    @text
#  end
#end





#delegation_tree = {}
#servers = {}
#
#roots.authority.each do |ns|
#
#  next if ns.type != Dnsruby::Types::NS
#
#  delegation = servers[ns.name.to_s] ||= {}
#  delegation_ns = delegation[ns.domainname.to_s] ||= []
#
#  # Search additional section for A and AAAA records
#  roots.additional.each do |addit|
#
#    if addit.name == ns.domainname &&
#       (addit.type == Dnsruby::Types::A || addit.type == Dnsruby::Types::AAAA)
#
#       puts "NS #{ns.name.to_s} #{addit.address}"
#
#       resolv2 = Dnsruby::Resolver.new(:recurse => false, :nameserver => addit.address.to_s)
#
#       msg = Dnsruby::Message.new
#       msg.header.rd = 0
#       msg.add_question(ns.name.to_s, Dnsruby::Types::SOA, Dnsruby::Classes::IN)
#       msg.do_caching = false
#       soa = resolv2.send_message(msg)
#
#       result = {
#         :type => addit.type,
#         :address => addit.address,
#       }
#
#       if soa.header.aa
#         result[:soa] = soa.answer.first.serial
#       else
#         result[:failure] = :lame
#       end
#
#       delegation_ns << result
#    end
#  end




log = Log.new
a = DnsTest::Tester.new(:log => log)

a.set_hints(nil)


a.query("news.uli.it.", "A")


