package option

type TLSTricksOptions struct {
	MixedCaseSNI bool `json:"mixedcase_sni,omitempty"`
	// PaddingMode/PaddingSize/PaddingSNI (hiddify-lineage TLS padding) removed
	// 2026-06-23 — they had no runtime consumer (dead). Only MixedCaseSNI is live.
}
