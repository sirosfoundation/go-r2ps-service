package service

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// R2PSRequestsTotal counts total R2PS requests by outcome.
	R2PSRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "r2ps",
		Name:      "requests_total",
		Help:      "Total R2PS requests by outcome.",
	}, []string{"outcome"})

	// R2PSRequestDuration tracks request processing duration in seconds.
	R2PSRequestDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: "r2ps",
		Name:      "request_duration_seconds",
		Help:      "R2PS request processing duration in seconds.",
		Buckets:   []float64{0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5},
	})

	// PAKEAuthTotal counts PAKE authentication outcomes.
	PAKEAuthTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "r2ps",
		Name:      "pake_auth_total",
		Help:      "Total PAKE authentication attempts by outcome.",
	}, []string{"outcome"})

	// HSMOperationsTotal counts HSM operations by type and outcome.
	HSMOperationsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "r2ps",
		Name:      "hsm_operations_total",
		Help:      "Total HSM operations by type and outcome.",
	}, []string{"operation", "outcome"})

	// HSMOperationDuration tracks HSM operation duration in seconds.
	HSMOperationDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "r2ps",
		Name:      "hsm_operation_duration_seconds",
		Help:      "HSM operation duration in seconds.",
		Buckets:   []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1},
	}, []string{"operation"})

	// ActiveSessions tracks the number of active PAKE sessions.
	ActiveSessions = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "r2ps",
		Name:      "active_sessions",
		Help:      "Number of active PAKE sessions.",
	})
)
