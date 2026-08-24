package serve

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	dto "github.com/prometheus/client_model/go"

	"github.com/varwof/engine/engine"
)

var (
	httpRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "pki_http_requests_total",
			Help: "Total HTTP requests by method, path, and status",
		},
		[]string{"method", "path", "status"},
	)

	httpRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "pki_http_request_duration_seconds",
			Help:    "HTTP request duration in seconds",
			Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
		},
		[]string{"method", "path"},
	)

	certIssuedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "pki_cert_issued_total",
			Help: "Total number of certificates issued, by CA and profile",
		},
		[]string{"ca", "profile"},
	)

	certRevokedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "pki_cert_revoked_total",
			Help: "Total number of certificates revoked, by CA",
		},
		[]string{"ca"},
	)

	certExpiringTotal = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "pki_cert_expiring_30d",
			Help: "Number of certificates expiring within 30 days, by CA",
		},
		[]string{"ca"},
	)

	ocspResponsesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "pki_ocsp_responses_total",
			Help: "Total OCSP responses by CA and status",
		},
		[]string{"ca", "status"},
	)

	tsaResponsesTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "pki_tsa_responses_total",
			Help: "Total TSA responses",
		},
	)

	activeCertsGauge = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "pki_active_certs",
			Help: "Number of currently valid (non-expired, non-revoked) certificates",
		},
	)

	revokedCertsGauge = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "pki_revoked_certs",
			Help: "Number of revoked certificates",
		},
	)

	caCountGauge = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "pki_cas_total",
			Help: "Number of configured certificate authorities",
		},
	)
)

func init() {
	prometheus.MustRegister(
		httpRequestsTotal,
		httpRequestDuration,
		certIssuedTotal,
		certRevokedTotal,
		certExpiringTotal,
		ocspResponsesTotal,
		tsaResponsesTotal,
		activeCertsGauge,
		revokedCertsGauge,
		caCountGauge,
	)
}

func metricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		dur := time.Since(start).Seconds()

		path := r.URL.Path
		if len(path) > 50 {
			path = path[:50]
		}

		httpRequestsTotal.WithLabelValues(r.Method, path, strconv.Itoa(rec.status)).Inc()
		httpRequestDuration.WithLabelValues(r.Method, path).Observe(dur)
	})
}

func (s *Server) metricsHandler() http.Handler {
	return metricsHandlerFor(s.getEngine)
}

// metricsHandler builds the Prometheus exposition handler. When a memory
// engine is present its varwof_engine_* metrics are merged into the output so one
// /metrics endpoint covers both DB and engine views.
func metricsHandler() http.Handler {
	return metricsHandlerFor(nil)
}

func metricsHandlerFor(getEngine func() *engine.Engine) http.Handler {
	gatherers := prometheus.Gatherers{prometheus.DefaultGatherer}
	if getEngine != nil && getEngine() != nil {
		gatherers = append(gatherers, engineMetricsGatherer{getEngine: getEngine})
	}
	return promhttp.HandlerFor(gatherers, promhttp.HandlerOpts{})
}

// engineMetricsGatherer exposes the in-memory engine's runtime metrics in Prometheus dto format.
// The engine in varwof-engine maintains zero external dependencies; here on the varwof-core side we
// translate its Metrics() snapshot into standard exposition, so the /metrics endpoint can output
// both pki_* and varwof_engine_* metrics.
type engineMetricsGatherer struct {
	getEngine func() *engine.Engine
}

func (g engineMetricsGatherer) Gather() ([]*dto.MetricFamily, error) {
	e := g.getEngine()
	if e == nil {
		return nil, nil
	}
	m := e.Metrics()
	asGauge := func(name, help string, v float64) *dto.MetricFamily {
		return &dto.MetricFamily{
			Name:   strPtr(name),
			Help:   strPtr(help),
			Type:   dto.MetricType_GAUGE.Enum(),
			Metric: []*dto.Metric{{Gauge: &dto.Gauge{Value: &v}}},
		}
	}
	asCounter := func(name, help string, v float64) *dto.MetricFamily {
		return &dto.MetricFamily{
			Name:   strPtr(name),
			Help:   strPtr(help),
			Type:   dto.MetricType_COUNTER.Enum(),
			Metric: []*dto.Metric{{Counter: &dto.Counter{Value: &v}}},
		}
	}
	return []*dto.MetricFamily{
		asGauge("varwof_engine_certindex_size", "Resident memory engine certificate index size", float64(m.CertIndexSize)),
		asGauge("varwof_engine_revokedset_size", "Resident memory engine revoked set size", float64(m.RevokedSetSize)),
		asGauge("varwof_engine_nonceset_size", "Resident memory engine nonce set size", float64(m.NonceSetSize)),
		asGauge("varwof_engine_danonceset_size", "Resident memory engine DA nonce set size", float64(m.DANonceSetSize)),
		asGauge("varwof_engine_subca_size", "Resident memory engine sub-CA index size", float64(m.SubCASize)),
		asGauge("varwof_engine_trustanchor_size", "Resident memory engine trust anchor index size", float64(m.TrustAnchorSize)),
		asGauge("varwof_engine_aic_size", "Resident memory engine AIC index size", float64(m.AICSize)),
		asGauge("varwof_engine_pipeline_pending", "Records pending in the engine write pipeline", float64(m.PipelinePending)),
		asCounter("varwof_engine_window_evictions_total", "Total engine window evictions", float64(m.WindowEvictions)),
		asCounter("varwof_engine_read_hit_total", "Total engine read hits", float64(m.ReadHits)),
		asCounter("varwof_engine_read_miss_total", "Total engine read misses", float64(m.ReadMisses)),
	}, nil
}

func strPtr(s string) *string { return &s }

func recordCertIssued(caName, profile string) {
	if profile == "" {
		profile = "default"
	}
	certIssuedTotal.WithLabelValues(caName, profile).Inc()
}

func recordCertRevoked(caName string) {
	certRevokedTotal.WithLabelValues(caName).Inc()
}

// RecordOCSPResponse records a produced OCSP response with CA and status
// dimensions. Exported so the OCSP handler (constructed in cmd/pki) can wire
// its MetricsHook into the serve metrics registry.
func RecordOCSPResponse(caName, status string) {
	ocspResponsesTotal.WithLabelValues(caName, status).Inc()
}

func updateInventoryMetrics(active, revoked float64) {
	activeCertsGauge.Set(active)
	revokedCertsGauge.Set(revoked)
}
