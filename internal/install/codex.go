package install

func planCodex(p Paths, bin string) (*pendingWrite, error) {
	doc, existed, err := readDoc(p.CodexHooks)
	if err != nil {
		return nil, err
	}
	changed := ensureHook(doc, "PermissionRequest", "", bin+" hook codex permission", 60)
	changed = ensureHook(doc, "Stop", "", bin+" hook codex stop", 0) || changed
	if !changed {
		return nil, nil
	}
	return &pendingWrite{path: p.CodexHooks, doc: doc, existed: existed}, nil
}

func planUninstallCodex(p Paths) (*pendingWrite, error) {
	doc, existed, err := readDoc(p.CodexHooks)
	if err != nil || !existed {
		return nil, err
	}
	if !removeHooks(doc) {
		return nil, nil
	}
	return &pendingWrite{path: p.CodexHooks, doc: doc, existed: true}, nil
}
