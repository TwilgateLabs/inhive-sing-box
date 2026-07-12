package option

import "github.com/sagernet/sing/common/json/badoption"

type MonitoringOptions struct {
	// Disabled полностью выключает создание OutboundMonitoring в box'е. Нужен для
	// probe/pingOnly-конфигов (side-instance проба + iOS standalone-хост): там
	// фоновый monitoring-контур паразитно гоняет свои URL-тесты через те же
	// outbound'ы, что меряет настоящая проба, и на общем xmux h2-клиенте (xhttp)
	// травит транспорт → io.ErrClosedPipe → false-×. Боевой туннель монитор
	// сохраняет (нужен mode-watcher'у). См. project_ping_arch_redesign.
	Disabled       bool               `json:"disabled,omitempty"`
	Interval       badoption.Duration `json:"interval,omitempty"`
	URLs           []string           `json:"urls,omitempty"` //H
	Workers        int                `json:"workers,omitempty"`
	DebounceWindow badoption.Duration `json:"debounce_window,omitempty"`
	URLTestTimeout badoption.Duration `json:"url_test_timeout,omitempty"`
	IdleTimeout    badoption.Duration `json:"idle_timeout,omitempty"`
}
