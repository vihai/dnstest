
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

    attr_accessor :ipv4
    attr_accessor :ipv6

    attr_accessor :tcp
    attr_accessor :udp

    attr_reader :trace
    attr_reader :zones

    def initialize(opts = {})
      @log = opts[:log] ? opts[:log] : NullLog.new
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

    #
    # trace format:
    # REQUEST = {
    #   :question => 'news.uli.it.',
    #   :question_class => 'IN',
    #   :question_type => 'A',
    #   :depth => 0,
    #   :found_zone => '',
    #   :found_authorities => {
    #     'a.root-servers.net.' => {
    #       '1.2.3.4' => {
    #         :udp => SOA_RECORD,
    #         :tcp => #<Dnsruby::OtherResolvError: recvfrom failed from 212.97.32.7; Connection refused - recvfrom(2)>
    #       }
    #     }
    #   },
    #   :found_serials => {
    #     '20110124021302' => {
    #       :chosen_authority => 'a.root-servers.net.',
    #       :chosen_authority_addr => '1.2.3.4',
    #       :chosen_authority_protocol => :udp,
    #       :kind => :referral,
    #       :response => RESPONSE,
    #       :sub => REQUEST,
    #     },
    #     '20110123030734' => {
    #       :chosen_authority => 'z.root-servers.net.',
    #       :chosen_authority_addr => '5.5.5.5',
    #       :chosen_authority_protocol => :udp,
    #       :kind => :cname,
    #       :response => RESPONSE,
    #       :sub => REQUEST,
    #     }
    #   }
    # }
    #
    # zones format:
    #
    # {
    #  'zone' =>
    #   {
    #    'authority.dns.name' =>
    #     {
    #      '1.2.3.4' =>
    #       {
    #        :udp => #<SOA response packet>
    #        :tcp => #<SOA response packet>
    #       }
    #     }
    #   }
    # }

    def run_test(name, type = Dnsruby::Types::A, klass = Dnsruby::Classes::IN, no_validation = false)

      @trace = { }
      @zones = { }

      # Make sure the hint servers are initialized.
      retrieve_root_zone

      normal_recursion(Question.new(name, type, klass), 0, no_validation, @trace)
  #    Dnsruby::Dnssec.validate(ret) if !no_validation
      #      print "\n\nRESPONSE:\n#{ret}\n"
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
      if !packet.header.qr
        raise "Response bit not set!"
      end

      if !packet.answer.empty?
        # We might have an answer but let's check if the label matches the question
        @log.debug "**** We got an answer! ****"

        packet.answer.each do |rr|
          # Bailiwick rule, do not cache if answer does not match question

          if rr.name == packet.question[0].qname
            # Cache the response
            @log.debug "Cacheing answer '#{rr}'"
            @cache << rr
          end
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

        # Scan again to see if there are CNAMEs
        packet.answer.each do |rr|
          if rr.type == Dnsruby::Types::CNAME &&
             rr.name == packet.question[0].qname

            # If we have a CNAME we recurse again
            @log.debug "**** Oh, it is a CNAME '#{rr.name}' => '#{rr.cname}', recurring for the aliased name ****"

            trace_block[:kind] = :cname
            trace_block[:response] = packet
            trace_block[:sub] = {}

            normal_recursion(Question.new(rr.cname, question.type, question.klass), depth + 1, true, trace_block[:sub])
            return
          end
        end

        @log.debug "**** We have our answer, yippieee ****"
        trace_block[:kind] = :answer
        trace_block[:response] = packet

      elsif !packet.authority.empty?
        @log.debug "**** We got a referral! ****"

  #      if !packet.header.aa
  #        trace[:log] << "We have a lame server!"
  #        raise LameServer
  #      end
  #
        packet.authority.each do |rr|
          next if rr.type != Dnsruby::Types::NS

          knz = Dnsruby::Name.create(known_zone)
          knz.absolute = true

          if rr.name != known_zone &&
             !rr.name.subdomain_of?(knz)
            raise "Bailiwick violation! Authority not subdomain of referral"
          end

          if !packet.question[0].qname.subdomain_of?(rr.name)
            raise "Bailiwick violation! Question is not subdomain of authority"
          end

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

        trace_block[:kind] = :referral
        trace_block[:response] = packet
        trace_block[:sub] = {}
        normal_recursion(question, depth + 1, true, trace_block[:sub])
      else
        raise "Whaaat?"
      end
    end

    def recursive_find_answer_in_trace(trace)
      trace[:found_serials].each do |soa_serial,q|
        if q[:kind] == :answer
          return q[:response]
        elsif q[:sub]
          return recursive_find_answer_in_trace(q[:sub])
        end
      end

      nil
    end

    def obtain_soa_for_authority(known_zone, authority, addr, resolver, trace_authority)

      protocol = resolver.use_tcp ? :tcp : :udp
      trace_authority[addr.address] = {}

      soa_packet = nil
      if @zones[known_zone] &&
         @zones[known_zone][authority] &&
         @zones[known_zone][authority][addr.address] &&
         @zones[known_zone][authority][addr.address][protocol]

        soa_packet = @zones[known_zone][authority][addr.address][protocol]

        @log.debug "Already have SOA record for zone #{known_zone}, avoid asking again"
      else
        @log.debug "Requesting SOA with #{resolver.use_tcp ? 'TCP' : 'UDP'} "
                   " for zone '#{known_zone}' to authority #{authority.nsdname}"
                   " using address #{addr.address}"

        @zones[known_zone] ||= {}
        @zones[known_zone][authority] ||= {}
        @zones[known_zone][authority][addr.address] ||= {}

        resolver.nameserver = addr.address.to_s
        qmsg = Dnsruby::Message.new(known_zone, SOA, IN)
        qmsg.header.rd = false
        qmsg.do_validation = false
        qmsg.do_caching = false

        begin
          soa_packet = resolver.send_message(qmsg)
        rescue Dnsruby::ResolvError, Dnsruby::OtherResolvError, IOError => e
          @zones[known_zone][authority][addr.address][protocol] = e
          trace_authority[addr.address][protocol] = e
          @log.debug "Server error #{e} for #{authority.nsdname}"
          return
        end
        @log.debug "SOA serial is #{soa_packet.answer[0].serial}"

        @zones[known_zone][authority][addr.address][protocol] = soa_packet
      end

      trace_authority[addr.address][protocol] = soa_packet.answer[0].serial
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
      rescue Dnsruby::ResolvError, Dnsruby::OtherResolvError => e
        trace_block[:error] = e
        @log.debug "Server error #{e} for #{authority}"
      else
        normal_recursion_handle_response(question, known_zone, packet, depth, trace_block)
      end
    end

    def normal_recursion(question, depth, no_validation, trace) # :nodoc:

      # TODO Lookup question in cache and return immediately if we already know it

      if depth > 255
        @log.error "Recursion too deep, aborting"
        raise RecursionTooDeep
      end

      trace[:question_name] = question.name
      trace[:question_type] = question.type
      trace[:question_class] = question.klass
      trace[:depth] = depth

      @log.debug ">>>>>>>"
      @log.debug "Recursion initiated, depth #{depth}, question '#{question.name}'"
      @log.debug "Searching for the most specific authority related to '#{question.name}'"

      known_zone, known_authorities = get_closest_zone(question.name)

      trace[:found_zone] = known_zone
      @log.debug "Found authorities for '#{known_zone}':"

      trace[:found_authorities] = {}
      known_authorities.each do |auth|
        trace[:found_authorities][auth.nsdname] = {}
        @log.debug "  #{auth.nsdname}"
      end

      known_authorities.each do |authority|

       trace_authority = trace[:found_authorities][authority.nsdname]

        ###################################
        # Check if we have A/AAAA records for the authority

        nsaddrs = @cache.find(authority.nsdname, [ A, AAAA ])
        if nsaddrs.empty?
          # TODO: Add check to see if there is a glue infinite loop
          @log.debug "#{authority.nsdname} does not have A/AAAA record in cache, recurse searching for it "

          trace_authority[:nsaddr_sub_a] ||= {}
          normal_recursion(Question.new(authority.nsdname, A, IN), depth + 1, true, trace_authority[:nsaddr_sub_a])
          a_answer = recursive_find_answer_in_trace(trace_authority[:nsaddr_sub_a])

          trace_authority[:nsaddr_sub_aaaa] ||= {}
          normal_recursion(Question.new(authority.nsdname, AAAA, IN), depth + 1, true, trace_authority[:nsaddr_sub_aaaa])
          aaaa_answer = recursive_find_answer_in_trace(trace_authority[:nsaddr_sub_aaaa])

          next if !a_answer && !aaaa_answer

          nsaddrs = a_answer.answer + aaaa_answer.answer
        else
          @log.debug "Authority #{authority.nsdname} has addresses #{nsaddrs.collect { |x| x.address.to_s }}"
        end

        @log.debug "Making request to authority #{authority.nsdname}"

        nsaddrs.each do |addr|
          next if addr.type == A && !@ipv4
          next if addr.type == AAAA && !@ipv6

          obtain_soa_for_authority(known_zone, authority, addr, @resolver_udp, trace_authority) if @udp
          obtain_soa_for_authority(known_zone, authority, addr, @resolver_tcp, trace_authority) if @tcp
        end
      end

      # Group all serials and pick an authority for each serial
      trace[:found_serials] ||= {}
      trace[:found_authorities].each do |authority,a|
        a.each do |address,b|
          b.each do |protocol,soa_serial|
            if !soa_serial.kind_of?(Exception)
              trace[:found_serials][soa_serial] = {
                :chosen_authority => authority,
                :chosen_authority_addr => address,
                :chosen_authority_protocol => protocol
              }
            end
          end
        end
      end

      @log.debug "Found #{trace[:found_serials].count} serials"

      trace[:found_serials].each do |soa_serial, trace_block|
        do_query_authority(question, known_zone,
                           trace_block[:chosen_authority],
                           trace_block[:chosen_authority_addr],
                           trace_block[:chosen_authority_protocol] == :tcp ? @resolver_tcp : @resolver_udp,
                           depth, trace, trace_block)
      end
    end
  end

end
