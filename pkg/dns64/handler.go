package dns64

import (
	"github.com/miekg/dns"
	"go.uber.org/zap"
	"golang.org/x/net/context"
	"nat64/internal"
	"slices"
	"time"
)

func (s *Server) Handler(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	switch r.Opcode {
	case dns.OpcodeQuery:
		res, errCode := s.resolveQuery(m)
		m.Answer = append(m.Answer, res...)
		m.Rcode = errCode
	}

	if err := w.WriteMsg(m); err != nil {
		s.logger.Warn(
			"Failed to write DNS response",
			zap.Error(err),
			zap.String("remote_addr", w.RemoteAddr().String()),
		)
		return
	}

	if err := w.Close(); err != nil {
		s.logger.Warn(
			"Failed to close DNS response writer",
			zap.Error(err),
			zap.String("remote_addr", w.RemoteAddr().String()),
		)
	}
}

func (s *Server) resolveQuery(m *dns.Msg) ([]dns.RR, int) {
	c := new(dns.Client)

	// Make a request to the recursive resolver
	recursiveRequest := new(dns.Msg)
	recursiveRequest.Id = dns.Id()
	recursiveRequest.RecursionDesired = true
	recursiveRequest.Question = make([]dns.Question, len(m.Question))
	copy(recursiveRequest.Question, m.Question)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	r, _, err := c.ExchangeContext(ctx, recursiveRequest, s.options.ResolverAddr)
	if err != nil {
		s.logger.Error("Failed to resolve DNS query", zap.Error(err), zap.Any("question", recursiveRequest.Question))
		return nil, dns.RcodeServerFailure
	}

	answer := r.Answer
	if answer == nil {
		answer = make([]dns.RR, 0)
	}

	if r.Rcode == dns.RcodeSuccess {
		// Check all AAAA questions have a response, and attempt to resolve A records if not
		for _, q := range recursiveRequest.Question {
			if q.Qtype == dns.TypeAAAA {
				hasAnswer := slices.ContainsFunc(r.Answer, func(record dns.RR) bool {
					return record.Header().Name == q.Name && record.Header().Rrtype == dns.TypeAAAA
				})

				if !hasAnswer {
					aRecords := s.requestARecords(q.Name)
					answer = append(answer, aRecords...)
				}
			}
		}
	}

	return answer, r.Rcode
}

func (s *Server) requestARecords(name string) []dns.RR {
	v4Question := new(dns.Msg)
	v4Question.SetQuestion(name, dns.TypeA)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	r, _, err := s.client.ExchangeContext(ctx, v4Question, s.options.ResolverAddr)
	if err != nil {
		s.logger.Error("Failed to resolve A records", zap.Error(err))
		return make([]dns.RR, 0)
	}

	answers := make([]dns.RR, 0, len(r.Answer))
	for _, record := range r.Answer {
		if record.Header().Rrtype == dns.TypeA {
			aRecord, ok := record.(*dns.A)
			if !ok {
				s.logger.Warn("Failed to cast record with type A to A record", zap.Any("record", record))
				continue
			}

			v6Addr := internal.IPv4ToNAT64(aRecord.A)

			s.logger.Debug(
				"Resolved A record to NAT64",
				zap.String("name", name),
				zap.String("v4_addr", aRecord.A.String()),
				zap.String("v6_addr", v6Addr.String()),
			)

			answers = append(answers, &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   name,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    record.Header().Ttl,
				},
				AAAA: v6Addr,
			})
		}
	}

	return answers
}
