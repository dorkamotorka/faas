// Copyright (c) Alex Ellis 2017. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go coldy coldy.c

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/gorilla/mux"
	"github.com/openfaas/faas-provider/auth"
	"github.com/openfaas/faas/gateway/handlers"
	"github.com/openfaas/faas/gateway/metrics"
	"github.com/openfaas/faas/gateway/pkg/middleware"
	"github.com/openfaas/faas/gateway/plugin"
	"github.com/openfaas/faas/gateway/scaling"
	"github.com/openfaas/faas/gateway/types"
	"github.com/openfaas/faas/gateway/version"
	natsHandler "github.com/openfaas/nats-queue-worker/handler"
)

func event(rd *ringbuf.Reader, scaler scaling.FunctionScaler) {
	for {
		record, err := rd.Read()
		if err != nil {
			panic(err)
		}

		data := binary.LittleEndian.Uint32(record.RawSample)
		fmt.Printf("Received from bpf event =>  %d\n", data)

		functionName := functionMap[int(data)]
		fmt.Printf("Function to call =>  %#v\n", functionName)

		namespace := "openfaas-fn"
		// Non-blocking call to scale
		res := scaler.Scale(functionName, namespace)
		if !res.Found {
			errStr := fmt.Sprintf("error finding function %s.%s: %s", functionName, namespace, res.Error.Error())
			log.Printf("Scaling in RingBuf Event: %s\n", errStr)
		}

		if res.Error != nil {
			errStr := fmt.Sprintf("error finding function %s.%s: %s", functionName, namespace, res.Error.Error())
			log.Printf("Scaling in RingBuf Event: %s\n", errStr)
		}
		fmt.Printf("Scale function in the RingBug Event returned - Available:  %t, Found: %t\n", res.Available, res.Found)
	}
}

// NameExpression for a function / service
const NameExpression = "-a-zA-Z_0-9."

var functionMap = map[int]string{8082: "env"}

func main() {
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	var ifname string
	flag.StringVar(&ifname, "i", "lo", "Network interface name where the eBPF program will be attached")
	flag.Parse()

	// Load the compiled eBPF ELF and load it into the kernel.
	var objs coldyObjects
	if err := loadColdyObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	} else {
		log.Println("Successfully loaded eBPF objects!")
	}
	defer objs.Close()

	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", ifname, err)
	}

	// Attach XDP program to the network interface.
	xdplink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpIngress,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatal("Attaching XDP:", err)
	} else {
		log.Println("XDP program should be attached!")
	}
	defer xdplink.Close()

	log.Printf("Pinning XDP BPF program")
	objs.XdpIngress.Pin("/sys/fs/bpf/coldy/xdp")

	// Attach count_packets to the network interface.
	tclink, err := link.AttachTCX(link.TCXOptions{
		Program:   objs.TcEgress,
		Attach:    ebpf.AttachTCXEgress,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatal("Attaching TC:", err)
	} else {
		log.Println("TC program should be attached!")
	}
	defer tclink.Close()

	log.Printf("Pinning TC BPF program")
	objs.TcEgress.Pin("/sys/fs/bpf/coldy/tc")

	log.Printf("Doing port remapping on %s..", ifname)

	rd, err := ringbuf.NewReader(objs.coldyMaps.Events)
	if err != nil {
		panic(err)
	}
	defer rd.Close()

	osEnv := types.OsEnv{}
	readConfig := types.ReadConfig{}
	config, configErr := readConfig.Read(osEnv)

	if configErr != nil {
		log.Fatalln(configErr)
	}
	if !config.UseExternalProvider() {
		log.Fatalln("You must provide an external provider via 'functions_provider_url' env-var.")
	}

	fmt.Printf("OpenFaaS Gateway - Community Edition (CE)\n"+
		"\nVersion: %s Commit: %s\nTimeouts: read=%s\twrite=%s\tupstream=%s\nFunction provider: %s\n\n",
		version.BuildVersion(),
		version.GitCommitSHA,
		config.ReadTimeout,
		config.WriteTimeout,
		config.UpstreamTimeout,
		config.FunctionsProviderURL)

	// credentials is used for service-to-service auth
	var credentials *auth.BasicAuthCredentials

	if config.UseBasicAuth {
		var readErr error
		reader := auth.ReadBasicAuthFromDisk{
			SecretMountPath: config.SecretMountPath,
		}
		credentials, readErr = reader.Read()

		if readErr != nil {
			log.Panicf(readErr.Error())
		}
	}

	var faasHandlers types.HandlerSet

	servicePollInterval := time.Second * 5

	metricsOptions := metrics.BuildMetricsOptions()
	exporter := metrics.NewExporter(metricsOptions, credentials, config.Namespace)
	exporter.StartServiceWatcher(*config.FunctionsProviderURL, metricsOptions, "func", servicePollInterval)
	metrics.RegisterExporter(exporter)

	// NOTE: This is the HTTP client
	reverseProxy := types.NewHTTPClientReverseProxy(config.FunctionsProviderURL,
		config.UpstreamTimeout,
		config.MaxIdleConns,
		config.MaxIdleConnsPerHost)

	loggingNotifier := handlers.LoggingNotifier{}

	prometheusNotifier := handlers.PrometheusFunctionNotifier{
		Metrics:           &metricsOptions,
		FunctionNamespace: config.Namespace,
	}

	functionNotifiers := []handlers.HTTPNotifier{loggingNotifier, prometheusNotifier}
	forwardingNotifiers := []handlers.HTTPNotifier{loggingNotifier}
	quietNotifier := []handlers.HTTPNotifier{}

	urlResolver := middleware.SingleHostBaseURLResolver{BaseURL: config.FunctionsProviderURL.String()}
	var functionURLResolver middleware.BaseURLResolver
	var functionURLTransformer middleware.URLPathTransformer
	nilURLTransformer := middleware.TransparentURLPathTransformer{}
	trimURLTransformer := middleware.FunctionPrefixTrimmingURLPathTransformer{}

	functionURLResolver = urlResolver
	functionURLTransformer = nilURLTransformer

	var serviceAuthInjector middleware.AuthInjector

	if config.UseBasicAuth {
		serviceAuthInjector = &middleware.BasicAuthInjector{Credentials: credentials}
	}

	// externalServiceQuery is used to query metadata from the provider about a function
	externalServiceQuery := plugin.NewExternalServiceQuery(*config.FunctionsProviderURL, serviceAuthInjector)

	scalingConfig := scaling.ScalingConfig{
		MaxPollCount:         uint(1000),
		SetScaleRetries:      uint(20),
		FunctionPollInterval: time.Millisecond * 100,
		CacheExpiry:          time.Millisecond * 250, // freshness of replica values before going stale
		ServiceQuery:         externalServiceQuery,
	}

	// This cache can be used to query a function's annotations.
	functionAnnotationCache := scaling.NewFunctionCache(scalingConfig.CacheExpiry)
	cachedFunctionQuery := scaling.NewCachedFunctionQuery(functionAnnotationCache, externalServiceQuery)

	// NOTE: Instantiates proxy to the FaaS provider
	faasHandlers.Proxy = handlers.MakeCallIDMiddleware(
		handlers.MakeForwardingProxyHandler(reverseProxy, functionNotifiers, functionURLResolver, functionURLTransformer, nil),
	)

	faasHandlers.ListFunctions = handlers.MakeForwardingProxyHandler(reverseProxy, forwardingNotifiers, urlResolver, nilURLTransformer, serviceAuthInjector)
	faasHandlers.DeployFunction = handlers.MakeForwardingProxyHandler(reverseProxy, forwardingNotifiers, urlResolver, nilURLTransformer, serviceAuthInjector)
	faasHandlers.DeleteFunction = handlers.MakeForwardingProxyHandler(reverseProxy, forwardingNotifiers, urlResolver, nilURLTransformer, serviceAuthInjector)
	faasHandlers.UpdateFunction = handlers.MakeForwardingProxyHandler(reverseProxy, forwardingNotifiers, urlResolver, nilURLTransformer, serviceAuthInjector)
	faasHandlers.FunctionStatus = handlers.MakeForwardingProxyHandler(reverseProxy, forwardingNotifiers, urlResolver, nilURLTransformer, serviceAuthInjector)

	faasHandlers.InfoHandler = handlers.MakeInfoHandler(handlers.MakeForwardingProxyHandler(reverseProxy, forwardingNotifiers, urlResolver, nilURLTransformer, serviceAuthInjector))
	faasHandlers.SecretHandler = handlers.MakeForwardingProxyHandler(reverseProxy, forwardingNotifiers, urlResolver, nilURLTransformer, serviceAuthInjector)

	faasHandlers.NamespaceListerHandler = handlers.MakeForwardingProxyHandler(reverseProxy, forwardingNotifiers, urlResolver, nilURLTransformer, serviceAuthInjector)

	faasHandlers.Alert = handlers.MakeNotifierWrapper(
		handlers.MakeAlertHandler(externalServiceQuery, config.Namespace),
		quietNotifier,
	)

	faasHandlers.LogProxyHandler = handlers.NewLogHandlerFunc(*config.LogsProviderURL, config.WriteTimeout)

	functionProxy := faasHandlers.Proxy

	// TODO: Remove comments from this if!
	//if config.ScaleFromZero {
	scalingFunctionCache := scaling.NewFunctionCache(scalingConfig.CacheExpiry)
	scaler := scaling.NewFunctionScaler(scalingConfig, scalingFunctionCache)
	functionProxy = handlers.MakeScalingHandler(functionProxy, scaler, scalingConfig, config.Namespace)
	//}

	if config.UseNATS() {
		log.Println("Async enabled: Using NATS Streaming")
		log.Println("Deprecation Notice: NATS Streaming is no longer maintained and won't receive updates from June 2023")

		maxReconnect := 60
		interval := time.Second * 2

		defaultNATSConfig := natsHandler.NewDefaultNATSConfig(maxReconnect, interval)

		natsQueue, queueErr := natsHandler.CreateNATSQueue(*config.NATSAddress, *config.NATSPort, *config.NATSClusterName, *config.NATSChannel, defaultNATSConfig)
		if queueErr != nil {
			log.Fatalln(queueErr)
		}

		faasHandlers.QueuedProxy = handlers.MakeNotifierWrapper(
			handlers.MakeCallIDMiddleware(handlers.MakeQueuedProxy(metricsOptions, natsQueue, trimURLTransformer, config.Namespace, cachedFunctionQuery)),
			forwardingNotifiers,
		)
	}

	prometheusQuery := metrics.NewPrometheusQuery(config.PrometheusHost, config.PrometheusPort, &http.Client{})
	faasHandlers.ListFunctions = metrics.AddMetricsHandler(faasHandlers.ListFunctions, prometheusQuery)
	faasHandlers.ScaleFunction = scaling.MakeHorizontalScalingHandler(handlers.MakeForwardingProxyHandler(reverseProxy, forwardingNotifiers, urlResolver, nilURLTransformer, serviceAuthInjector))

	// TODO: Remove comments from this if!
	/*
		if credentials != nil {
			faasHandlers.Alert =
				auth.DecorateWithBasicAuth(faasHandlers.Alert, credentials)
			faasHandlers.UpdateFunction =
				auth.DecorateWithBasicAuth(faasHandlers.UpdateFunction, credentials)
			faasHandlers.DeleteFunction =
				auth.DecorateWithBasicAuth(faasHandlers.DeleteFunction, credentials)
			faasHandlers.DeployFunction =
				auth.DecorateWithBasicAuth(faasHandlers.DeployFunction, credentials)
			faasHandlers.ListFunctions =
				auth.DecorateWithBasicAuth(faasHandlers.ListFunctions, credentials)
			faasHandlers.ScaleFunction =
				auth.DecorateWithBasicAuth(faasHandlers.ScaleFunction, credentials)
			faasHandlers.FunctionStatus =
				auth.DecorateWithBasicAuth(faasHandlers.FunctionStatus, credentials)
			faasHandlers.InfoHandler =
				auth.DecorateWithBasicAuth(faasHandlers.InfoHandler, credentials)
			faasHandlers.SecretHandler =
				auth.DecorateWithBasicAuth(faasHandlers.SecretHandler, credentials)
			faasHandlers.LogProxyHandler =
				auth.DecorateWithBasicAuth(faasHandlers.LogProxyHandler, credentials)
			faasHandlers.NamespaceListerHandler =
				auth.DecorateWithBasicAuth(faasHandlers.NamespaceListerHandler, credentials)
		}
	*/

	r := mux.NewRouter()
	// max wait time to start a function = maxPollCount * functionPollInterval

	r.HandleFunc("/function/{name:["+NameExpression+"]+}", functionProxy)
	r.HandleFunc("/function/{name:["+NameExpression+"]+}/", functionProxy)
	r.HandleFunc("/function/{name:["+NameExpression+"]+}/{params:.*}", functionProxy)

	r.HandleFunc("/system/info", faasHandlers.InfoHandler).Methods(http.MethodGet)
	r.HandleFunc("/system/alert", faasHandlers.Alert).Methods(http.MethodPost)

	r.HandleFunc("/system/function/{name:["+NameExpression+"]+}", faasHandlers.FunctionStatus).Methods(http.MethodGet)
	r.HandleFunc("/system/functions", faasHandlers.ListFunctions).Methods(http.MethodGet)
	r.HandleFunc("/system/functions", faasHandlers.DeployFunction).Methods(http.MethodPost)
	r.HandleFunc("/system/functions", faasHandlers.DeleteFunction).Methods(http.MethodDelete)
	r.HandleFunc("/system/functions", faasHandlers.UpdateFunction).Methods(http.MethodPut)
	r.HandleFunc("/system/scale-function/{name:["+NameExpression+"]+}", faasHandlers.ScaleFunction).Methods(http.MethodPost)

	r.HandleFunc("/system/secrets", faasHandlers.SecretHandler).Methods(http.MethodGet, http.MethodPut, http.MethodPost, http.MethodDelete)
	r.HandleFunc("/system/logs", faasHandlers.LogProxyHandler).Methods(http.MethodGet)

	r.HandleFunc("/system/namespaces", faasHandlers.NamespaceListerHandler).Methods(http.MethodGet)

	if faasHandlers.QueuedProxy != nil {
		r.HandleFunc("/async-function/{name:["+NameExpression+"]+}/", faasHandlers.QueuedProxy).Methods(http.MethodPost)
		r.HandleFunc("/async-function/{name:["+NameExpression+"]+}", faasHandlers.QueuedProxy).Methods(http.MethodPost)
		r.HandleFunc("/async-function/{name:["+NameExpression+"]+}/{params:.*}", faasHandlers.QueuedProxy).Methods(http.MethodPost)
	}

	fs := http.FileServer(http.Dir("./assets/"))

	// This URL allows access from the UI to the OpenFaaS store
	allowedCORSHost := "raw.githubusercontent.com"
	fsCORS := handlers.DecorateWithCORS(fs, allowedCORSHost)

	uiHandler := http.StripPrefix("/ui", fsCORS)
	if credentials != nil {
		r.PathPrefix("/ui/").Handler(
			auth.DecorateWithBasicAuth(uiHandler.ServeHTTP, credentials)).
			Methods(http.MethodGet)
	} else {
		r.PathPrefix("/ui/").Handler(uiHandler).
			Methods(http.MethodGet)
	}

	//Start metrics server in a goroutine
	go runMetricsServer()

	r.HandleFunc("/healthz",
		handlers.MakeForwardingProxyHandler(reverseProxy, forwardingNotifiers, urlResolver, nilURLTransformer, serviceAuthInjector)).Methods(http.MethodGet)

	r.Handle("/", http.RedirectHandler("/ui/", http.StatusMovedPermanently)).Methods(http.MethodGet)

	tcpPort := 8080

	s := &http.Server{
		Addr:           fmt.Sprintf(":%d", tcpPort),
		ReadTimeout:    config.ReadTimeout,
		WriteTimeout:   config.WriteTimeout,
		MaxHeaderBytes: http.DefaultMaxHeaderBytes, // 1MB - can be overridden by setting Server.MaxHeaderBytes.
		Handler:        r,
	}

	go event(rd, scaler)
	/* BPF event thread */

	fmt.Println(s.ListenAndServe())
}

// runMetricsServer Listen on a separate HTTP port for Prometheus metrics to keep this accessible from
// the internal network only.
func runMetricsServer() {
	metricsHandler := metrics.PrometheusHandler()
	router := mux.NewRouter()
	router.Handle("/metrics", metricsHandler)
	router.HandleFunc("/healthz", handlers.HealthzHandler)

	port := 8082
	readTimeout := 5 * time.Second
	writeTimeout := 5 * time.Second

	s := &http.Server{
		Addr:           fmt.Sprintf(":%d", port),
		ReadTimeout:    readTimeout,
		WriteTimeout:   writeTimeout,
		MaxHeaderBytes: http.DefaultMaxHeaderBytes,
		Handler:        router,
	}

	fmt.Println(s.ListenAndServe())
}
