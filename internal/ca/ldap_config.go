package ca

type LDAPConfig struct {
	URL          string `json:"url,omitempty"`
	BindDN       string `json:"bind_dn,omitempty"`
	BindPassword string `json:"bind_password,omitempty"`
	BaseDN       string `json:"base_dn,omitempty"`
	Filter       string `json:"filter,omitempty"`
	UIDAttr      string `json:"uid_attr,omitempty"`
	MapCN        string `json:"map_cn,omitempty"`
	MapOrg       string `json:"map_o,omitempty"`
	MapOU        string `json:"map_ou,omitempty"`
	MapL         string `json:"map_l,omitempty"`
	MapST        string `json:"map_st,omitempty"`
	MapC         string `json:"map_c,omitempty"`
	MapEmail     string `json:"map_email,omitempty"`
}
