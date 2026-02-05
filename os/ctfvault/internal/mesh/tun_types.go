package mesh

type TunOptions struct {
	Listen    string
	Target    string
	Device    string
	CIDR      string
	PeerCIDR  string
	PSK       string
	PSKFile   string
	Transport string
}
