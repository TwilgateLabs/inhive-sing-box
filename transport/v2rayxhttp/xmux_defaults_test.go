package xhttp

import (
	"testing"

	Xbadoption "github.com/sagernet/sing-box/common/xray/json/badoption"
	"github.com/sagernet/sing-box/option"
)

// TestApplyXmuxDefaults_MatchesXrayReference — гард на значения xmux-дефолтов.
//
// ЗАЧЕМ: это значение дрейфовало три раза подряд (Xray 26.1.13 maxConcurrency
// 1..1 → 26.7.11 maxConnections 6..6 → 26.9.9 maxConnections 3..3), и каждый
// раз никто не замечал, потому что ничто в дереве его не проверяло. Дефолт
// определяет ширину warm-пула h2-соединений на КАЖДОМ CDN-конфиге без явного
// xmux (а это все наши CDN-бэкенды) и меняет и throughput, и отпечаток для DPI.
//
// Числа ниже — из эталона core/upstream.toml (id="xhttp", сейчас v26.9.9,
// infra/conf/transport_method.go SplitHTTPConfig.Build). Меняешь эталон —
// меняй здесь ТЕМ ЖЕ коммитом и записывай причину в divergences реестра.
func TestApplyXmuxDefaults_MatchesXrayReference(t *testing.T) {
	var x option.V2RayXHTTPXmuxOptions
	applyXmuxDefaults(&x)

	want := map[string]Xbadoption.Range{
		// 18e28390 «Reduce default maxConnections from 6 to 3 for anti-TSPU».
		"MaxConnections":   {From: 3, To: 3},
		"HMaxRequestTimes": {From: 600, To: 900},
		"HMaxReusableSecs": {From: 1800, To: 3000},
	}
	got := map[string]Xbadoption.Range{
		"MaxConnections":   x.MaxConnections,
		"HMaxRequestTimes": x.HMaxRequestTimes,
		"HMaxReusableSecs": x.HMaxReusableSecs,
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s = %+v, want %+v (эталон Xray v26.9.9; см. upstream.toml id=xhttp)", k, got[k], w)
		}
	}
	// Дефолты подменяют ТОЛЬКО пустой блок; maxConcurrency с maxConnections
	// взаимоисключающие, и дефолт не должен трогать concurrency вовсе.
	if x.MaxConcurrency != (Xbadoption.Range{}) {
		t.Errorf("MaxConcurrency must stay zero when defaults apply, got %+v", x.MaxConcurrency)
	}
}
