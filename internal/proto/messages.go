package proto

// EventPayload is the plaintext sealed inside an event envelope.
type EventPayload struct {
	Title   string `json:"title"`
	Body    string `json:"body"`
	Command string `json:"command,omitempty"`
	Detail  string `json:"detail,omitempty"`
	Agent   string `json:"agent"`
	Project string `json:"project"`
	Cwd     string `json:"cwd"`
	Pane    string `json:"pane,omitempty"`
	Session string `json:"session"`
}

// DeviceEnv is one phone's copy of a sealed payload.
type DeviceEnv struct {
	DeviceID string   `json:"deviceId"`
	Env      Envelope `json:"env"`
}

// EventMsg is host → relay: one envelope per linked phone.
type EventMsg struct {
	T         string      `json:"t"` // "event"
	ID        string      `json:"id"`
	Kind      string      `json:"kind"`
	Agent     string      `json:"agent"`
	Thread    string      `json:"thread"`
	Envs      []DeviceEnv `json:"envs"`
	ExpiresIn int         `json:"expiresIn,omitempty"`
}

// UsageMsg is host → relay.
type UsageMsg struct {
	T    string      `json:"t"` // "usage"
	Envs []DeviceEnv `json:"envs"`
}

// RelayMsg is relay → host: "ack", "decision", "ssh-enroll", "unlink" (and "down" from the link itself).
type RelayMsg struct {
	T        string    `json:"t"`
	ID       string    `json:"id"`
	DeviceID string    `json:"deviceId,omitempty"`
	Pushed   bool      `json:"pushed"`
	Env      *Envelope `json:"env,omitempty"`
}

// SSHEnrolledMsg is host → relay: the sealed SSHReply.
type SSHEnrolledMsg struct {
	T        string   `json:"t"` // "ssh-enrolled"
	DeviceID string   `json:"deviceId"`
	Env      Envelope `json:"env"`
}

// UnlinkedMsg is host → relay: the unlink was applied; the relay stops replaying it.
type UnlinkedMsg struct {
	T        string `json:"t"` // "unlinked"
	DeviceID string `json:"deviceId"`
}

// DecisionPayload is the plaintext the phone seals; AAD is DecisionAAD(hostId, eventId).
type DecisionPayload struct {
	ID       string `json:"id"`
	Decision string `json:"decision"` // allow | deny | always
}
