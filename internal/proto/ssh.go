package proto

// Address is one way to reach the Mac: "lan" (LocalHostName.local or the LAN IPv4) or "tailscale" (IP or MagicDNS name).
type Address struct {
	Kind string `json:"kind"`
	Host string `json:"host"`
}

// SSHEnroll is the phone's sealed request (AAD SSHAAD).
type SSHEnroll struct {
	SSHPublicKey string `json:"sshPublicKey"`
	DeviceName   string `json:"deviceName"`
}

// SSHReply is the helper's sealed answer (AAD SSHReplyAAD).
type SSHReply struct {
	User      string    `json:"user"`
	Port      int       `json:"port"`
	Addresses []Address `json:"addresses"`
	HostKeys  []string  `json:"hostKeys"`
	TmuxPath  string    `json:"tmuxPath"`
}

func SSHAAD(hostID, deviceID string) string      { return hostID + "|ssh|" + deviceID }
func SSHReplyAAD(hostID, deviceID string) string { return hostID + "|ssh-reply|" + deviceID }
