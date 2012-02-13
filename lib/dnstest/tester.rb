
module DnsTest

IN = Dnsruby::Classes::IN
ANY = Dnsruby::Types::ANY
A = Dnsruby::Types::A
AAAA = Dnsruby::Types::AAAA
NS = Dnsruby::Types::NS
SOA = Dnsruby::Types::SOA

class Question
  attr_accessor :name
  attr_accessor :type
  attr_accessor :klass

  def initialize(name, type = A, klass = IN)
    name = Dnsruby::Name.create(name) if !name.kind_of?(Dnsruby::Name)

    @name = name
    @type = type
    @klass = klass
  end
end

class Tester

  class NullLog
    def debug(str) ; end
    def info(str) ; end
    def warn(str) ; end
  end

  attr_reader :hints
  # The resolver to use for the queries
  attr_accessor :resolver

  attr_accessor :log

  attr_accessor :ipv4
  attr_accessor :ipv6

  attr_accessor :tcp
  attr_accessor :udp

  attr_accessor :include_packets
  attr_accessor :include_packets_text

  attr_reader :trace
  attr_reader :zones

  def initialize(opts = {})
    @hints = nil
    @cache = RRCache.new
    @system_resolver = Dnsruby::Resolver.new

    @resolver_udp = Dnsruby::Resolver.new
    @resolver_udp.do_caching = false
    @resolver_udp.recurse = false

    @resolver_tcp = Dnsruby::Resolver.new
    @resolver_tcp.do_caching = false
    @resolver_tcp.recurse = false
    @resolver_tcp.use_tcp = true

    @ipv4 = true
    @ipv6 = true
    @udp = true
    @tcp = true
    @log = NullLog.new

    @include_packets = true
    @include_packets_text = true

    opts.each { |k,v| send("#{k.to_s}=", v) }
  end

  #Initialize the hint servers.  Recursive queries need a starting name
  #server to work off of. This method takes a list of IP addresses to use
  #as the starting servers.  These name servers should be authoritative for
  #the root (.) zone.
  #
  #  res.hints=(ips)
  #
  #If no hints are passed, the default nameserver is asked for the hints.
  #Normally these IPs can be obtained from the following location:
  #
  #  ftp://ftp.internic.net/domain/named.root
  #

  class RecursorError < StandardError ; end
  class HintNotAuthoritativeForRoot < RecursorError ; end
  class MissingHints < RecursorError ; end
  class NoResponseFromAnyAuthority < RecursorError ; end
  class RecursionTooDeep < RecursorError ; end
  class LameServer < RecursorError ; end

  def cache_hints_from_system_resolver
    # get at least a root server NS from system's recursor
    @system_resolver.recurse = true

    packet = @system_resolver.query('.', NS)

    nameservers = packet.answer.select { |rr| rr.type == NS }

    raise MissingHints if nameservers.empty?

    @cache << nameservers
    @cache << packet.additional.select { |rr| rr.type == Dnsruby::Types::A || rr.type == Dnsruby::Types::AAAA }

    nses = @cache.find('', Dnsruby::Types::NS)

    raise MissingHints if nses.size == 0

    if nses.map { |x| @cache.find(x.nsdname.to_s, [ A, AAAA ]) }.flatten.empty?
      # Gee, the nameserver didn't give anything in the additional section, well, ask him again for an A or AAAA, thanks
      res = @system_resolver.query(packet.answer[0].nsdname, Dnsruby::Types::A)
      @cache << res.answer

      res = @system_resolver.query(packet.answer[0].nsdname, Dnsruby::Types::AAAA)
      @cache << res.answer
    end

    if nses.map { |x| @cache.find(x.nsdname.to_s, [ A, AAAA ]) }.flatten.empty?
      raise MissingHints
    end
  end


  def retrieve_root_zone

    cache_hints_from_system_resolver

    # Now, we have at least one root server IP address. Ask one of them for an authoritative list of NS for the root
    @resolver_udp.nameserver = @cache.find('', NS).map { |x| @cache.find(x.nsdname, [ A, AAAA ]).
                                                   map { |y| y.address.to_s } }.flatten

    # Do a query from one of the (hinted) root servers, the authoritative response will override the hints
    qmsg = Dnsruby::Message.new('.', ANY, IN)
    qmsg.header.rd = false
    qmsg.do_validation = false
    qmsg.do_caching = false
    packet = @resolver_udp.send_message(qmsg)

    @cache << packet.answer
    @cache << packet.additional

#      if !packet.header.aa
#        raise 'What? Root server not authoritative for root?!?'
#      end

    # Fine, the cache is initialized with root servers
  end

  def clear_cache
    @cache.clear
  end

  def run_test(name, type = Dnsruby::Types::A, klass = Dnsruby::Classes::IN, no_validation = false)

    @trace = { }
    @zones = { }

    name = name + '.' if name[-1..-1] != '.'

    # Make sure the hint servers are initialized.
    retrieve_root_zone

    return normal_recursion(Question.new(name, type, klass), 0, no_validation, @trace)
  end

  def find_answer_in_trace
    recursive_find_answer_in_trace(@trace)
  end

  private

  def get_closest_zone(name)
    name_split = name.to_s.split('.')

    name_split.count.downto(0) do |i|
      zone = name_split.last(i).join('.')
      if @cache[zone]
        ns_records = @cache[zone].select { |rr| rr.type == Dnsruby::Types::NS }
        return zone, ns_records if !ns_records.empty?
      end
    end
  end

  def normal_recursion_handle_response(question, known_zone, packet, depth, trace_block)
    trace_block[:response_packet] = packet if @include_packets
    trace_block[:response_packet_text] = packet.to_s if @include_packets_text

    if !packet.header.qr
      raise "Response bit not set!"
    end

    if packet.header.aa
      @log.debug "**** We got an authoritative answer! ****"

      # Cache the answer
      packet.answer.each do |rr|
        # Bailiwick rule, do not cache if answer does not match question

        if rr.name == question.name &&
           (rr.type == question.type || question.type == Dnsruby::Types::ANY) &&
           rr.klass == question.klass
          # Cache the response
          @log.debug "Cacheing answer '#{rr}'"
          @cache << rr
        end
      end

      # Cache the additional data
      packet.additional.each do |rr|
        knz = Dnsruby::Name.create(known_zone)
        knz.absolute = true

        if rr.name != known_zone &&
           !rr.name.subdomain_of?(knz)
          @log.debug "Not caching '#{rr}' because it's not under #{known_zone}" unless rr.type == Dnsruby::Types::OPT
          next
        end

        if rr.type == Dnsruby::Types::A || rr.type == Dnsruby::Types::AAAA
          @log.debug "Cacheing additional '#{rr}'"
          @cache << rr
        end
      end

      # Scan again to see if there are CNAMEs
      packet.answer.each do |rr|
        if rr.type == Dnsruby::Types::CNAME &&
           rr.name == packet.question[0].qname

          # If we have a CNAME we recurse again
          @log.debug "**** Oh, it is a CNAME '#{rr.name}' => '#{rr.cname}', recurring for the aliased name ****"

          trace_block[:kind] = :cname
          trace_block[:cname_dest] = rr.cname
          trace_block[:sub] = {}

          return normal_recursion(Question.new(rr.cname, question.type, question.klass), depth + 1, true, trace_block[:sub])
        end
      end

      # Search for answer to our question
      packet.answer.each do |rr|
        # Bailiwick rule, do not cache if answer does not match question

        if rr.name == question.name &&
           (rr.type == question.type || question.type == Dnsruby::Types::ANY) &&
           rr.klass == question.klass
          @log.debug "**** We have our answer, yippieee ****"
          trace_block[:kind] = :answer
          trace_block[:answer_packet] = packet if @include_packets
          trace_block[:answer_packet_text] = packet if @include_packets_text

          return packet
        end
      end

      @log.debug "The answer does not contain the record we were looking for :("
      trace_block[:kind] = :answer_without_record

      return packet

    elsif !packet.authority.empty?
      @log.debug "**** We got a referral! ****"

      trace_block[:kind] = :referral
      trace_block[:refer_to] = {}

      packet.authority.each do |rr|
        if rr.type != Dnsruby::Types::NS
          @log.warn "WARN: authority section contains non-NS records?"
          trace_block[:notes] ||= ''
          trace_block[:notes] += "Authority section contains non-NS record #{rr.name} #{rr.klass} #{rr.type}\n"
          next
        end

        knz = Dnsruby::Name.create(known_zone)
        knz.absolute = true

        trace_block[:refer_to][rr.name.to_s] ||= {}
        refto = trace_block[:refer_to][rr.name.to_s]

        if rr.name != known_zone &&
           !rr.name.subdomain_of?(knz)
          refto[:valid] = false
          refto[:notes] ||= ''
          refto[:notes] +=
            "Bailiwick violation! Authority #{rr.name} not subdomain of referral #{knz}\n"
          @log.warn "Bailiwick violation! Authority #{rr.name} not subdomain of referral #{knz}"
          next
        end

        if question.name != rr.name &&
           !question.name.subdomain_of?(rr.name)
          refto[:valid] = false
          refto[:notes] ||= ''
          refto[:notes] += "Bailiwick violation! Question #{question.name} is not subdomain of authority #{rr.name}\n"
          @log.warn "Bailiwick violation! Question #{question.name} is not subdomain of authority #{rr.name}"
          next
        end

        refto[:valid] = true
        refto[:servers] ||= []
        refto[:servers] << rr.nsdname.to_s

        @log.debug "Cacheing authority '#{rr}'"
        @cache << rr
      end

      packet.additional.each do |rr|
        knz = Dnsruby::Name.create(known_zone)
        knz.absolute = true

        if rr.name != known_zone &&
           !rr.name.subdomain_of?(knz)

          @log.debug "Not caching '#{rr}' because it's not under #{known_zone}" unless rr.type == Dnsruby::Types::OPT

          next
        end

        if rr.type == Dnsruby::Types::A || rr.type == Dnsruby::Types::AAAA
          @log.debug "Cacheing additional '#{rr}'"
          @cache << rr
        end
      end

      trace_block[:sub] = {}

      return normal_recursion(question, depth + 1, true, trace_block[:sub])
    end

    raise "Whaaat?"
  end

  def recursive_find_answer_in_trace(trace)
    trace[:found_authorities].each do |auth_name,auth_addrs|
      auth_addrs.each do |auth_addr,auth_protos|
        next if auth_addr == :nsaddr_sub_a || auth_addr == :nsaddr_sub_aaaa

        auth_protos.each do |auth_proto,auth|

          next if auth[:error]

          if auth[:kind] == :answer
            return auth[:answer_data]
          elsif auth[:sub]
            return recursive_find_answer_in_trace(auth[:sub])
          end
        end
      end
    end

    nil
  end

  def obtain_soa_for_authority(known_zone, authority, addr, resolver, trace_authority)

    protocol = resolver.use_tcp ? :tcp : :udp
    auth_name = authority.nsdname.to_s
    auth_addr = addr.address.to_s

    trace_authority[auth_addr] = {}

    soa_packet = nil
    if @zones[known_zone] &&
       @zones[known_zone][auth_name] &&
       @zones[known_zone][auth_name][auth_addr] &&
       @zones[known_zone][auth_name][auth_addr][protocol]

      soa_packet = @zones[known_zone][auth_name][auth_addr][protocol]

      @log.debug "Already have SOA record for #{known_zone}/#{auth_name}/#{auth_addr}/#{protocol}," +
                 " avoiding asking again"
    else
      @log.debug "Requesting SOA for #{known_zone}/#{auth_name}/#{auth_addr}/#{protocol}"
      @zones[known_zone] ||= {}
      @zones[known_zone][auth_name] ||= {}
      @zones[known_zone][auth_name][auth_addr] ||= {}

      resolver.nameserver = auth_addr
      qmsg = Dnsruby::Message.new(known_zone, SOA, IN)
      qmsg.header.rd = false
      qmsg.do_validation = false
      qmsg.do_caching = false

      begin
        soa_packet = resolver.send_message(qmsg)
      rescue Dnsruby::ResolvError, Dnsruby::ResolvTimeout, Dnsruby::OtherResolvError, IOError => e
        @zones[known_zone][auth_name][auth_addr][protocol] = e
        trace_authority[auth_addr][protocol] = { :error => e.class.name.split('::').last.upcase }
        @log.debug "Server error #{e} for #{authority.nsdname}"
        return
      end

      @log.debug "SOA serial is #{soa_packet.answer[0].serial}"

      @zones[known_zone][auth_name][auth_addr][protocol] = soa_packet
    end

    if soa_packet.kind_of?(Exception)
      trace_authority[auth_addr][protocol] = { :error => soa_packet.class.name.split('::').last.upcase }
    else
      trace_authority[auth_addr][protocol] = {
        :serial => soa_packet.answer[0].serial,
      }

      trace_authority[auth_addr][protocol][:soa_packet] = soa_packet if @include_packets
      trace_authority[auth_addr][protocol][:soa_packet_text] = soa_packet.to_s if @include_packets_text
    end
  end

  def do_query_authority(question, known_zone, authority, addr, resolver, depth, trace, trace_block)

    ###################################
    # Now make the real request

    @log.debug "Asking to #{authority} for '#{question.name}' using address '#{addr}'"

    resolver.nameserver = addr.to_s
    qmsg = Dnsruby::Message.new(question.name, question.type, question.klass)
    qmsg.header.rd = false
    qmsg.do_validation = false
    qmsg.do_caching = false

    begin
      packet = resolver.send_message(qmsg)
    rescue Dnsruby::ResolvError, Dnsruby::ResolvTimeout, Dnsruby::OtherResolvError, IOError => e
      trace_block[:error] = e.class.name.split('::').last.upcase
      @log.warn "Server error #{e.to_s} for #{authority}"
      return nil
    end

    trace_block[:chosen] = true

    return normal_recursion_handle_response(question, known_zone, packet, depth, trace_block)
  end

  def normal_recursion(question, depth, no_validation, trace) # :nodoc:

    # TODO Lookup question in cache and return immediately if we already know it

    if depth > 64
      @log.error "Recursion too deep, aborting"
      raise RecursionTooDeep
    end

    trace[:question_name] = question.name
    trace[:question_type] = question.type
    trace[:question_class] = question.klass
    trace[:depth] = depth

    @log.debug ">>>>>>>"
    @log.debug "Recursion initiated, depth #{depth}, question '#{question.name} #{question.klass.to_s} #{question.type.to_s}'"
    @log.debug "Searching for the most specific authority related to '#{question.name}'"

    known_zone, known_authorities = get_closest_zone(question.name)

    trace[:found_zone] = known_zone
    @log.debug "Found authorities for '#{known_zone}':"

    trace[:found_authorities] = {}
    known_authorities.each do |auth|
      trace[:found_authorities][auth.nsdname.to_s] = {}
      @log.debug "  #{auth.nsdname}"
    end

    known_authorities.each do |authority|

      trace_authority = trace[:found_authorities][authority.nsdname.to_s]

      ###################################
      # Check if we have A/AAAA records for the authority

      nsaddrs = @cache.find(authority.nsdname, [ A, AAAA ])
      if nsaddrs.empty?
        # TODO: Add check to see if there is a glue infinite loop
        @log.debug "#{authority.nsdname} does not have A/AAAA record in cache, recurse searching for it "

        @log.debug "Recurring for #{authority.nsdname} IN A"
        trace_authority[:nsaddr_sub_a] ||= {}
        a_answer = normal_recursion(Question.new(authority.nsdname, A, IN), depth + 1, true, trace_authority[:nsaddr_sub_a])

        @log.debug "Recurring for #{authority.nsdname} IN AAAA"
        trace_authority[:nsaddr_sub_aaaa] ||= {}
        aaaa_answer = normal_recursion(Question.new(authority.nsdname, AAAA, IN), depth + 1, true, trace_authority[:nsaddr_sub_aaaa])

        if (!a_answer || a_answer.answer.empty?) &&
           (!aaaa_answer || aaaa_answer.answer.empty?)
          @log.warn "No A or AAAA response found!"
          next
        end

        nsaddrs = []
        nsaddrs += a_answer.answer if a_answer
        nsaddrs += aaaa_answer.answer if aaaa_answer
      else
        @log.debug "Authority #{authority.nsdname} has addresses #{nsaddrs.collect { |x| x.address.to_s }}"
      end

      @log.debug "Requesting SOA for authority #{authority.nsdname} for all addresses/protocols"

      nsaddrs.each do |addr|
        next if addr.type == A && !@ipv4
        next if addr.type == AAAA && !@ipv6

        obtain_soa_for_authority(known_zone, authority, addr, @resolver_udp, trace_authority) if @udp
        obtain_soa_for_authority(known_zone, authority, addr, @resolver_tcp, trace_authority) if @tcp
      end
    end

#      # Group all serials and pick an authority for each serial
#      trace[:found_serials] ||= []
#      trace[:found_authorities].each do |authority,a|
#        a.each do |address,b|
#          b.each do |protocol,auth|
#            if !auth.kind_of?(Exception)
#              trace[:found_serials][auth[:serial].to_s] = {
#                :chosen_authority => authority,
#                :chosen_authority_addr => address,
#                :chosen_authority_protocol => protocol
#              }
#            end
#          end
#        end
#      end
#
#      @log.debug "Found #{trace[:found_serials].count} serials"


    trace[:found_authorities].each do |auth_name,auth_addrs|
      auth_addrs.each do |auth_addr,auth_protos|
        next if auth_addr == :nsaddr_sub_a || auth_addr == :nsaddr_sub_aaaa

        auth_protos.each do |auth_proto,auth|

          next if auth[:error] # There already was an error while asking for SOA

          res = do_query_authority(question, known_zone, auth_name, auth_addr,
                             auth_proto == :tcp ? @resolver_tcp : @resolver_udp,
                             depth, trace, auth)

          return res if res
        end
      end
    end

    @log.debug "No authority gave me an answer !??!"

    return nil
  end
end

end
