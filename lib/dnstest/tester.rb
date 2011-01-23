
module DnsTest

  IN = Dnsruby::Classes::IN
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

    attr_accessor :callback, :recurse, :ipv6_ok
    attr_reader :hints
    # The resolver to use for the queries
    attr_accessor :resolver

    attr_reader :trace

    def initialize(opts = {})
      @log = opts[:log] ? opts[:log] : NullLog.new
      @hints = nil
      @cache = RRCache.new
      @system_resolver = Dnsruby::Resolver.new
      @resolver = Dnsruby::Resolver.new

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


    def set_hints(hints = nil)

  raise "TO BE IMPLEMENTED" if hints

      cache_hints_from_system_resolver

      # Now, we have at least one root server IP address. Ask one of them for an authoritative list of NS for the root
      @resolver.do_caching = false
      @resolver.recurse = false
      @resolver.nameserver = @cache.find('', [ A, AAAA ]).map { |x| x.address.to_s }

      # Do a query from one of the (hinted) root servers, the authoritative response will override the hints
      packet = Dnsruby::Resolver.new.query('.', NS, IN)

#      if !packet.header.aa
#        raise 'What? Root server not authoritative for root?!?'
#      end

      # Fine, the cache is initialized with root servers
    end

    def clear_cache
      @cache.clear
    end

    def run_test(name, type = Dnsruby::Types::A, klass = Dnsruby::Classes::IN, no_validation = false)

      # Make sure the hint servers are initialized.
      set_hints if @cache.empty?

      @trace = { }
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
          return zone, @cache[zone].select { |rr| rr.type == Dnsruby::Types::NS }
        end
      end
    end

    def normal_recursion_handle_response(question, known_zone, packet, depth, trace)
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

            trace[:kind] = :cname
            trace[:response] = packet
            trace[:sub] = {}

            normal_recursion(Question.new(rr.cname, question.type, question.klass), depth + 1, true, trace[:sub])
            return
          end
        end

        @log.debug "**** We have our answer, yippieee ****"
        trace[:kind] = :answer
        trace[:response] = packet

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

        trace[:kind] = :referral
        trace[:response] = packet
        trace[:sub] = {}
        normal_recursion(question, depth + 1, true, trace[:sub])
      else
        raise "Whaaat?"
      end
    end

    def recursive_find_answer_in_trace(trace)
      trace[:queries].each do |q|
        if q[:kind] == :answer
          return q[:response]
        elsif q[:sub]
          return recursive_find_answer_in_trace(q[:sub])
        end
      end

      nil
    end

    def normal_recursion(question, depth, no_validation, trace) # :nodoc:

      # TODO Lookup question in cache and return immediately if we already know it

      if depth > 255
        @log.error "Recursion too deep, aborting"
        raise RecursionTooDeep
      end

      trace[:name] = question.name
      trace[:depth] = depth
      trace[:found_authorities] = []

      @log.debug ">>>>>>>"
      @log.debug "Recursion initiated, depth #{depth}, question '#{question.name}'"
      @log.debug "Searching for the most specific authority related to '#{question.name}'"

      known_zone, known_authorities = get_closest_zone(question.name)

      trace[:known_zone] = known_zone
      @log.debug "Found authorities for '#{known_zone}':"

      trace[:found_authorities] = []
      known_authorities.each do |auth|
        trace[:found_authorities] << auth.nsdname
        @log.debug "  #{auth.nsdname}"
      end

      trace[:queries] = []

      known_authorities.each do |authority|

        ###################################
        # Check if we have A/AAAA records for the authority

        nsaddrs = @cache.find(authority.nsdname, [ A, AAAA ])
        if nsaddrs.empty?
          # TODO: Add check to see if there is a glue infinite loop
          @log.debug "#{authority.nsdname} does not have A/AAAA record in cache, recurse searching for it "

          current_query[:nsaddr_sub_a] ||= {}
          normal_recursion(authority.nsdname, A, IN, depth + 1, true, current_query[:nsaddr_sub_a])
          a_answer = recursive_find_answer_in_trace(current_query[:nsaddr_sub_a])

          current_query[:nsaddr_sub_aaaa] ||= {}
          normal_recursion(authority.nsdname, A, IN, depth + 1, true, current_query[:nsaddr_sub_aaaa])
          aaaa_answer = recursive_find_answer_in_trace(current_query[:nsaddr_sub_aaaa])

          next if !a_answer && !aaaa_answer

          nsaddrs = a_answer.answer + aaaa_answer.answer
        else
          @log.debug "Authority #{authority.nsdname} has addresses #{nsaddrs.collect { |x| x.address.to_s }}"
        end

        @log.debug "Making request to authority #{authority.nsdname}"

        nsaddrs.each do |addr|

          current_query = {}
          current_query[:authority] = authority.nsdname
          current_query[:address] = addr.address

          ###################################
          # Obtain SOA for this zone

          @log.debug "Requesting SOA for zone '#{known_zone}' to authority #{authority.nsdname} using address #{addr.address}"

          @resolver.nameserver = addr.address.to_s
          qmsg = Dnsruby::Message.new(known_zone, SOA, IN)
          qmsg.header.rd = false
          qmsg.do_validation = false
          qmsg.do_caching = false

          begin
            soa_packet = @resolver.send_message(qmsg)
          rescue Dnsruby::ResolvError, Dnsruby::OtherResolvError => e
            current_query[:error] = e
            current_query[:time] = 1123
            @log.debug "Server error #{e} for #{authority.nsdname}"
            next
          end
          @log.debug "SOA serial is #{soa_packet.answer[0].serial}"

          current_query[:soa] = soa_packet

          if !(trace[:queries].collect { |x| x[:soa].answer[0].serial }.include?(soa_packet.answer[0].serial))

            ###################################
            # Now make the real request

            @log.debug "Asking to #{authority.nsdname} for '#{question.name}' using address '#{addr.address}'"

            @resolver.nameserver = addr.address.to_s
            qmsg = Dnsruby::Message.new(question.name, question.type, question.klass)
            qmsg.header.rd = false
            qmsg.do_validation = false
            qmsg.do_caching = false

            begin
              packet = @resolver.send_message(qmsg)
            rescue Dnsruby::ResolvError, Dnsruby::OtherResolvError => e
              current_query[:error] = e
              current_query[:time] = 1123
              @log.debug "Server error #{e} for #{authority.nsdname}"
              next
            end

            normal_recursion_handle_response(question, known_zone, packet, depth, current_query)
          else
            @log.debug "Not recurring into this auhtority since SOA #{soa_packet.answer[0].serial} has already been recurred"
          end

          trace[:queries] << current_query
        end
      end
    end
  end

end
