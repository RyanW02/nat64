package dns64

import (
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

type Server struct {
	options Options
	logger  *zap.Logger
	client  *dns.Client
}

type Options struct {
	UseTCP       bool
	BindAddr     string
	ResolverAddr string
}

func NewServer(options Options, logger *zap.Logger) *Server {
	return &Server{
		options: options,
		logger:  logger,
		client:  new(dns.Client),
	}
}

func (s *Server) Run() {
	dns.HandleFunc(".", s.Handler)

	if s.options.UseTCP {
		go func() {
			s.logger.Info("Starting TCP server", zap.String("bind_address", s.options.BindAddr))

			if err := dns.ListenAndServe(s.options.BindAddr, "tcp", nil); err != nil {
				s.logger.Fatal("Failed to setup the TCP server", zap.Error(err), zap.String("bind_address", s.options.BindAddr))
			}
		}()
	}

	go func() {
		s.logger.Info("Starting UDP server", zap.String("bind_address", s.options.BindAddr))

		if err := dns.ListenAndServe(s.options.BindAddr, "udp", nil); err != nil {
			s.logger.Fatal("Failed to setup the UDP server", zap.Error(err), zap.String("bind_address", s.options.BindAddr))
		}
	}()
}
