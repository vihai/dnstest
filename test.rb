#! /usr/bin/ruby

$:.unshift File.join(File.dirname( __FILE__), 'lib')

require 'dnstest'
require 'pp'

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


def filter_trace(trace)
  trace[:found_serials].each do |soa_serial,q|
    q[:response].instance_eval do
      def pretty_print(pp)
        pp.text '<Filtered...>'
      end
    end

    if q[:sub]
      filter_trace(q[:sub])
    end
  end
end

log = Log.new
a = DnsTest::Tester.new(:log => log)
a.tcp = false
a.run_test("news.uli.it.", "A")

puts "############# Result ##########"
filter_trace a.trace
pp a.trace

puts "############# Answer ##########"
puts a.find_answer_in_trace
#puts "############# Authorities #########"
#pp a.zones
puts "###############################"

