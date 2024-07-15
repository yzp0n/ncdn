package types

import (
	"encoding/json"
	"log/slog"
)

func (p *PoPInfo) FormatWebUIJson() []byte {
	in := struct {
		Id         string `json:"id"`
		Ip4        string `json:"ip4"`
		UIPopupCSS string `json:"ui_popup_css"`
	}{
		Id:         p.Id,
		Ip4:        p.Ip4.String(),
		UIPopupCSS: p.UIPopupCSS,
	}
	bs, err := json.Marshal(&in)
	if err != nil {
		slog.Error("Failed to marshal PoPInfo", slog.String("error", err.Error()))
		panic(err)
	}
	return bs
}

func (r *RegionInfo) FormatWebUIJson() []byte {
	prefices := make([]string, len(r.Prefices))
	for i, p := range r.Prefices {
		prefices[i] = p.String()
	}

	in := struct {
		Id         string   `json:"id"`
		Prefices   []string `json:"prefices"`
		UIPopupCSS string   `json:"ui_popup_css"`
	}{
		Id:         r.Id,
		Prefices:   prefices,
		UIPopupCSS: r.UIPopupCSS,
	}
	bs, err := json.Marshal(&in)
	if err != nil {
		slog.Error("Failed to marshal RegionInfo", slog.String("error", err.Error()))
		panic(err)
	}
	return bs
}
